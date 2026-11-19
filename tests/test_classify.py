"""Task 6: Java/Spring classification (registry-side, not API filter).

Classification is deterministic (rules + tech_aliases seed), never an LLM
call. CPE vendor/product come from the seed CSV, whose entries are the
NVD CPE dictionary forms (vmware:spring_boot / vmware:spring_framework /
apache:tomcat / apache:log4j) — never guessed.
"""

import csv

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.classify import (
    SEED_CSV,
    apply_classification,
    classify_from_text,
    classify_java_spring,
    classify_vuln_class,
    classify_writeup_class,
    load_aliases_from_csv,
    load_aliases_from_db,
    reclassify_unclassified,
    reclassify_writeup,
    seed_tech_aliases,
)
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.models import Base, TechAlias, Writeup, WriteupVuln

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"


@pytest.fixture()
def session():
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.fail(
            "Test database 'eunoia_test' is missing or unreachable. "
            "Create it with: bash scripts/setup_test_db.sh "
            "(see README.md, 'Test database')."
        )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


def _writeup(**overrides):
    data = {
        "canonical_url": "https://hackerone.com/reports/1",
        "url_hash": "a" * 64,
        "title": "t",
    }
    data.update(overrides)
    return Writeup(**data)


# --- Verbatim brief tests -------------------------------------------------

def test_spring_boot_writeup_classified():
    c = classify_java_spring({"title": "SSRF via PDF parser in Spring Boot 3.2.0", "excerpt": "Tomcat 10.1", "cwe_ids": ["CWE-918"]})
    assert "spring-boot" in c.tech and c.confidence > 0.5


def test_wordpress_writeup_not_java():
    c = classify_java_spring({"title": "Stored XSS on WordPress", "excerpt": "wp-admin"})
    assert c.tech == []


# --- Tech matching ----------------------------------------------------------

def test_log4j_writeup_classified_with_apache_cpe():
    c = classify_java_spring({"title": "RCE via Log4Shell in log4j-core 2.14.1"})
    assert "log4j" in c.tech
    assert "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*" in c.cpe
    assert "org.apache.logging.log4j:log4j-core" in c.package


def test_spring_framework_and_version_in_cpe():
    c = classify_java_spring({"title": "RCE in Spring Framework 5.3.18"})
    assert "spring-framework" in c.tech
    assert "cpe:2.3:a:vmware:spring_framework:5.3.18:*:*:*:*:*:*:*" in c.cpe


def test_version_absent_keeps_wildcard_cpe():
    c = classify_java_spring({"title": "SSRF in Spring Boot app"})
    assert "spring-boot" in c.tech
    assert "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*" in c.cpe


def test_maven_package_mention_matches_tech():
    c = classify_java_spring({"title": "XSS", "excerpt": "deployed on org.apache.tomcat.embed:tomcat-embed-core"})
    assert "tomcat" in c.tech


def test_bare_spring_word_does_not_match():
    # "Spring" alone is too generic (could be a season, a mattress, ...):
    # only the full "spring boot" / "spring framework" phrases match.
    c = classify_java_spring({"title": "Spring cleaning XSS in the park"})
    assert c.tech == []


def test_evidence_names_field_and_phrase():
    c = classify_java_spring({"title": "SSRF via PDF parser in Spring Boot 3.2.0"})
    assert any("title" in e and "spring boot" in e for e in c.evidence)


# --- Vuln class -------------------------------------------------------------

def test_vuln_class_from_cwe():
    assert classify_vuln_class(["CWE-918"]) == "SSRF"
    assert classify_vuln_class(["CWE-79"]) == "XSS"
    assert classify_vuln_class(["CWE-89"]) == "SQLi"
    assert classify_vuln_class(["CWE-502"]) == "Deserialization"


def test_unmapped_cwe_is_unclassified_and_needs_review():
    c = classify_java_spring({"title": "Weird bug in Spring Boot", "cwe_ids": ["CWE-999999"]})
    assert c.vuln_class == "unclassified"
    assert c.needs_review is True


def test_no_cwe_is_unclassified():
    # No CWE anywhere AND no technique named in the title: honestly
    # unclassified. (T7 changed the old contract: a title that NAMES
    # its technique, e.g. "SSRF in Spring Boot", now classifies from
    # the text — see test_t7_bare_acronym_names_the_class.)
    c = classify_java_spring({"title": "Weird behaviour in Spring Boot login"})
    assert c.vuln_class == "unclassified"
    assert c.needs_review is True


def test_t7_bare_acronym_names_the_class():
    """T7: a bare technique acronym in the title IS the report naming
    its class — same signal as the spelled-out technique name, and
    the reason the MVP-era 'no CWE means unclassified' contract was
    superseded (22-27% of real rows have no CWE at all)."""
    c = classify_java_spring({"title": "SSRF in Spring Boot"})
    assert c.vuln_class == "SSRF"
    assert classify_writeup_class(
        "SSRF in Spring Boot", "", []) == ("SSRF", "text")
    c2 = classify_java_spring({"title": "TikTok 2FA Bypass"})
    assert c2.vuln_class == "Auth Bypass"
    c3 = classify_java_spring({"title": "ReDoS in IPAddr"})
    assert c3.vuln_class == "DoS"
    c4 = classify_java_spring({"title": "Clickjacking vulnerability"})
    assert c4.vuln_class == "Clickjacking"
    assert classify_vuln_class(["CWE-1021"]) == "Clickjacking"


def test_t7_text_fallback_order_specific_technique_first():
    """T7: first match wins — a report naming two techniques is the
    specific one, not the generic bypass/auth word in the same title."""
    assert classify_from_text(
        "Unauthenticated SSRF via Public Reference API", "") == "SSRF"
    assert classify_from_text(
        "MongoDB Query Logs & Schema Leak via Unauthenticated Endpoint",
        "") == "Info Disclosure"


def test_t7_nvd_cwe_gaps_mapped():
    """T7: CWEs NVD actually returns for the 506-row corpus rows that
    the old map left unclassified (verified against NVD on
    19 Nov 2026 — CVE-2025-15079 CWE-297, CVE-2024-45818 CWE-667,
    CVE-2023-27706 CWE-312, CVE-2022-35931 CWE-261, CVE-2023-27536
    CWE-305/CWE-287)."""
    assert classify_vuln_class(["CWE-297"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-305"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-261"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-312"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-667"]) == "DoS"
    assert classify_vuln_class(["CWE-1021"]) == "Clickjacking"


def test_t7_second_wave_phrases():
    """T7: phrases for the remaining NULL-CWE rows, each observed in
    a real disclosed title of the 506-row corpus (19 Nov 2026)."""
    assert classify_from_text(
        "Unrestricted File Upload on reddit.secure.force.com",
        "") == "Unrestricted File Upload"
    assert classify_from_text(
        "IPv4 only clusters susceptible to MitM attacks via IPv6 "
        "rogue router advertisements", "") == "Auth Bypass"
    assert classify_from_text(
        "imap: StartTLS stripping attack", "") == "Auth Bypass"
    assert classify_from_text(
        "CVE-2023-32001: fopen race condition", "") == "Race Condition"
    assert classify_from_text(
        "Overwrite any file of the web server", "") == "Path Traversal"
    assert classify_from_text(
        "Domain does not Match SSL Certificate", "") == "Auth Bypass"
    assert classify_from_text(
        "No Valid SPF Records at sifchain.finance", "") == "Auth Bypass"
    assert classify_from_text(
        "HTTP Digest nonce reused across an https->http scheme change",
        "") == "Auth Bypass"
    assert classify_from_text(
        "State Isolation Failure in Multiplexed Connections "
        "(Shared Auth Context)", "") == "Auth Bypass"
    assert classify_from_text(
        "old session does not expire after password change",
        "") == "Auth Bypass"
    assert classify_from_text(
        "HackerOne Staging uses Production data for testing",
        "") == "Info Disclosure"
    assert classify_from_text(
        "Without verifying email and activate account, user can "
        "perform all action", "") == "Auth Bypass"
    assert classify_from_text(
        "SSTI in Jinja template", "") == "SSTI"


# --- Seed CSV + tech_aliases table ------------------------------------------

def test_seed_csv_has_the_four_mandated_technologies():
    aliases = load_aliases_from_csv()
    techs = {a.technology for a in aliases}
    assert {"spring-boot", "spring-framework", "tomcat", "log4j"} <= techs
    # Every CPE is a well-formed CPE 2.3 application entry, never guessed:
    # vendor/product are the NVD dictionary forms.
    for a in aliases:
        assert a.cpe.startswith("cpe:2.3:a:"), a.cpe
        assert a.package_name, a.technology


def test_seed_is_idempotent(session):
    assert seed_tech_aliases(session) == 4
    assert seed_tech_aliases(session) == 0
    assert session.query(TechAlias).count() == 4


def test_classify_from_db_aliases(session):
    seed_tech_aliases(session)
    aliases = load_aliases_from_db(session)
    c = classify_java_spring(
        {"title": "SSRF via PDF parser in Spring Boot 3.2.0", "excerpt": "Tomcat 10.1"},
        aliases=aliases,
    )
    assert "spring-boot" in c.tech and "tomcat" in c.tech


# --- apply_classification (Task 5 handoff) ----------------------------------

def test_apply_creates_writeup_vuln_when_missing(session):
    # Task 5: a writeup with no CWE/CVE/severity/bounty gets NO WriteupVuln
    # row at all, so classification must CREATE one, not update one.
    # With no CWE anywhere and no technique named in the title, the
    # honest class is "unclassified" (the spec quality gate), not a
    # guess from the title. (T7: a title that DOES name its technique
    # now classifies from the text — this title names none.)
    w = _writeup(title="Weird behaviour in PDF parser in Spring Boot 3.2.0")
    session.add(w)
    session.commit()
    apply_classification(session, w)
    session.commit()
    rows = session.query(WriteupVuln).filter_by(writeup_id=w.id).all()
    assert len(rows) == 1
    assert rows[0].vuln_class == "unclassified"


def test_apply_create_path_carries_cwe_cve_and_program(session):
    """Final review triage, Task 6: the create path used to lose the
    CWE/CVE (it re-read them from the bare writeup) and omitted the
    program. The values derived for classification are now carried
    through to the created row."""
    import types

    w = _writeup(title="SSRF via PDF parser")
    session.add(w)
    session.commit()
    # A writeup carrying cwe/cve/program attributes (the values the
    # worker derives from the payload): the created row must keep them.
    carrying = types.SimpleNamespace(
        id=w.id, title=w.title, excerpt="",
        cwe_ids=["CWE-918"], cve_ids=["CVE-2022-22965"],
        program="Acme Spring",
    )
    apply_classification(session, carrying)
    session.commit()
    row = session.query(WriteupVuln).filter_by(writeup_id=w.id).one()
    assert row.vuln_class == "SSRF"
    assert row.cwe_id == "CWE-918"
    assert row.cve_id == "CVE-2022-22965"
    assert row.program == "Acme Spring"
    assert row.program_slug == "acme-spring"


def test_classify_uses_program_field_for_tech(session):
    """Final review triage, Task 6: apply_classification passes the
    program through to the classifier, so a technology mentioned
    only in the program counts for tech detection."""
    c = classify_java_spring({
        "title": "SSRF via PDF parser",
        "excerpt": "",
        "program": "Spring Boot app",
        "cwe_ids": ["CWE-918"],
    })
    assert "spring-boot" in c.tech
    assert c.vuln_class == "SSRF"


def test_apply_fills_null_vuln_class_on_existing_row(session):
    w = _writeup(title="RCE via Log4Shell in log4j-core 2.14.1")
    session.add(w)
    session.commit()
    session.add(WriteupVuln(writeup_id=w.id, vuln_class=None, cwe_id="CWE-917"))
    session.commit()
    apply_classification(session, w)
    session.commit()
    row = session.query(WriteupVuln).filter_by(writeup_id=w.id).one()
    assert row.vuln_class == "RCE"


# --- T7: expanded CWE taxonomy -------------------------------------------
# Data-driven from the live corpus (19 Nov 2026): the 50-row production
# corpus had 20 unclassified rows, and a 100-item Hacktivity probe had
# 56 unclassified — all from CWEs the old 13-class map did not cover
# (CSRF, DoS, info disclosure, memory safety, cert validation, ...) or
# from a NULL CWE. Every mapping below is the CWE's own definition,
# not a guess: CWE-352 *is* CSRF, CWE-400 *is* uncontrolled resource
# consumption (DoS), CWE-200 *is* information exposure, and so on.

def test_t7_new_cwe_mappings():
    assert classify_vuln_class(["CWE-352"]) == "CSRF"
    assert classify_vuln_class(["CWE-400"]) == "DoS"
    assert classify_vuln_class(["CWE-770"]) == "DoS"
    assert classify_vuln_class(["CWE-200"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-201"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-209"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-212"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-359"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-488"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-311"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-319"]) == "Info Disclosure"
    assert classify_vuln_class(["CWE-125"]) == "Memory Safety"
    assert classify_vuln_class(["CWE-122"]) == "Memory Safety"
    assert classify_vuln_class(["CWE-416"]) == "Memory Safety"
    assert classify_vuln_class(["CWE-119"]) == "Memory Safety"
    assert classify_vuln_class(["CWE-787"]) == "Memory Safety"
    assert classify_vuln_class(["CWE-295"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-304"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-294"]) == "Auth Bypass"
    assert classify_vuln_class(["CWE-269"]) == "Privilege Escalation"
    assert classify_vuln_class(["CWE-93"]) == "Injection"
    assert classify_vuln_class(["CWE-113"]) == "Injection"
    assert classify_vuln_class(["CWE-444"]) == "Request Smuggling"
    assert classify_vuln_class(["CWE-601"]) == "Open Redirect"
    assert classify_vuln_class(["CWE-434"]) == "Unrestricted File Upload"


def test_t7_cwe_still_wins_over_text():
    # CWE-79 says XSS even when the title also mentions another
    # technique word; the CWE is the authoritative signal.
    cls, source = classify_writeup_class(
        "Reflected XSS via request smuggling vector",
        "", ["CWE-79"])
    assert cls == "XSS"
    assert source == "cwe"


# --- T7: text fallback for NULL-CWE rows -----------------------------------
# Only fires when no CWE (HackerOne or NVD) maps to a class. Phrases
# are strict, literal technique names observed in real disclosed
# titles — never a single generic word like "bypass" or "leak" alone.

def test_t7_text_fallback_memory_safety():
    cls, source = classify_writeup_class(
        "Stack Buffer Overflow in MariaDB CONNECT storage engine",
        "", [])
    assert (cls, source) == ("Memory Safety", "text")
    cls, source = classify_writeup_class(
        "Connector/ODBC: long version string causes heap out-of-bounds write",
        "", [])
    assert (cls, source) == ("Memory Safety", "text")


def test_t7_text_fallback_auth_bypass_and_info_disclosure():
    cls, _ = classify_writeup_class(
        "KILL authorization trusts the presented login name instead of "
        "the authenticated anonymous account", "", [])
    assert cls == "Auth Bypass"
    cls, _ = classify_writeup_class(
        "Taskcluster web-server OAuth2 authorization codes are reusable",
        "", [])
    assert cls == "Auth Bypass"
    cls, _ = classify_writeup_class(
        "Unauthenticated team export ignores donor privacy settings, "
        "exposing donor data", "", [])
    assert cls == "Info Disclosure"
    cls, _ = classify_writeup_class(
        "CVE-2026-11856: cross-origin Digest auth state leak", "", [])
    assert cls == "Info Disclosure"


def test_t7_text_fallback_request_smuggling_and_injection():
    cls, _ = classify_writeup_class(
        "HTTP Request Smuggling via Connection: close in Node.js llhttp parser",
        "", [])
    assert cls == "Request Smuggling"
    cls, _ = classify_writeup_class(
        "SMTP CRLF injection in custom SMTP recipient operand", "", [])
    assert cls == "Injection"


def test_t7_text_fallback_stays_unclassified_without_a_phrase():
    # "Open Email Relay" and curl-internal quirks name no class in the
    # taxonomy: honestly unclassified beats a guessed class.
    cls, source = classify_writeup_class(
        "Open Email Relay on WordPress Gutenberg Plugin via formAction "
        "parameter leads to phishing and spam campaigns", "", [])
    assert (cls, source) == ("unclassified", "unclassified")
    cls, _ = classify_writeup_class(
        "HTTP upload resume offset consumed twice after early 307 redirect",
        "", [])
    assert cls == "unclassified"


def test_t7_apply_classification_uses_text_fallback(session):
    w = _writeup(title="Stack Buffer Overflow in MariaDB CONNECT engine")
    session.add(w)
    session.commit()
    row = apply_classification(session, w)
    assert row.vuln_class == "Memory Safety"


# --- T7: reclassify existing unclassified rows -----------------------------

def test_t7_reclassify_upgrades_only_unclassified(session):
    w = _writeup(title="CSRF on settings form")
    session.add(w)
    session.commit()
    session.add(WriteupVuln(writeup_id=w.id, vuln_class="unclassified",
                            cwe_id="CWE-352"))
    session.add(WriteupVuln(writeup_id=w.id, vuln_class="XSS",
                            cwe_id="CWE-79"))
    session.commit()
    # The unclassified row upgrades to CSRF; the mapped XSS row is
    # never overwritten by a reclassification pass.
    changed = reclassify_writeup(session, w)
    assert changed == ("unclassified", "CSRF")
    rows = session.query(WriteupVuln).filter_by(writeup_id=w.id).all()
    assert sorted(r.vuln_class for r in rows) == ["CSRF", "XSS"]


def test_t7_reclassify_unclassified_counts(session):
    w1 = _writeup(title="CSRF on settings form")
    w2 = _writeup(title="Open Email Relay on WordPress",
                  canonical_url="https://hackerone.com/reports/2",
                  url_hash="b" * 64)
    session.add_all([w1, w2])
    session.commit()
    session.add(WriteupVuln(writeup_id=w1.id, vuln_class="unclassified",
                            cwe_id="CWE-352"))
    session.add(WriteupVuln(writeup_id=w2.id, vuln_class="unclassified",
                            cwe_id=None))
    session.commit()
    checked, changed = reclassify_unclassified(session)
    assert checked == 2
    assert changed == 1
    assert session.query(WriteupVuln).filter_by(
        writeup_id=w1.id).one().vuln_class == "CSRF"
    assert session.query(WriteupVuln).filter_by(
        writeup_id=w2.id).one().vuln_class == "unclassified"
