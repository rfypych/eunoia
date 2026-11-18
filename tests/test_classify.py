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
    classify_java_spring,
    classify_vuln_class,
    load_aliases_from_csv,
    load_aliases_from_db,
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
    c = classify_java_spring({"title": "SSRF in Spring Boot"})
    assert c.vuln_class == "unclassified"
    assert c.needs_review is True


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
    # With no CWE anywhere, the honest class is "unclassified" (the spec
    # quality gate), not a guess from the title.
    w = _writeup(title="SSRF via PDF parser in Spring Boot 3.2.0")
    session.add(w)
    session.commit()
    apply_classification(session, w)
    session.commit()
    rows = session.query(WriteupVuln).filter_by(writeup_id=w.id).all()
    assert len(rows) == 1
    assert rows[0].vuln_class == "unclassified"


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
