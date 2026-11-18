"""Task 3: core schema (§5.4) — tables exist, constraints hold, enums match spec."""

import uuid

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.models import (
    Base,
    CveCache,
    RunLesson,
    Source,
    Writeup,
    WriteupVuln,
)

# Tests run against a dedicated database, never the dev database:
# the fixture creates/drops all tables, which would otherwise leave the
# dev DB empty (alembic still stamped at head) after every test run.
TEST_DATABASE_URL = "postgresql+psycopg://eunoia@localhost:5432/eunoia_test"


@pytest.fixture()
def session():
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
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


def test_canonical_url_unique(session):
    session.add(_writeup())
    session.commit()
    session.add(_writeup(title="t2"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_url_hash_unique(session):
    session.add(_writeup())
    session.commit()
    session.add(_writeup(canonical_url="https://hackerone.com/reports/2"))
    with pytest.raises(IntegrityError):
        session.commit()


def test_writeup_defaults_to_active_and_has_api_id(session):
    w = _writeup()
    session.add(w)
    session.commit()
    assert w.status == "active"
    assert w.api_id.startswith("w_")
    assert isinstance(w.id, uuid.UUID) and w.id.version == 7


def test_writeup_vuln_carries_spec_fields(session):
    session.add(_writeup())
    session.commit()
    v = WriteupVuln(
        writeup_id=session.query(Writeup).one().id,
        vuln_class="SSRF",
        cwe_id="CWE-918",
        cve_id="CVE-2021-44228",
        cvss_score=9.1,
        severity="critical",
        severity_source="hackerone",
        bounty_amount=5000,
        bounty_currency="USD",
        bounty_verified=True,
        verified_against="hackerone",
        program="Example",
        program_slug="example",
    )
    session.add(v)
    session.commit()
    assert v.bounty_verified is True


def test_sources_auth_ref_is_a_name_not_a_secret(session):
    session.add(Source(id="hackerone", name="HackerOne Hacktivity", type="api",
                       auth_ref="hackerone/api-token"))
    session.commit()
    assert session.query(Source).one().auth_ref == "hackerone/api-token"


def test_all_spec_tables_exist(session):
    tables = set(inspect(session.get_bind()).get_table_names())
    assert {
        "writeups", "writeup_vulns", "sources", "writeup_sources",
        "raw_captures", "writeup_events", "embeddings", "takedowns",
        "tech_aliases", "cve_cache", "jobs", "source_hosts", "run_lessons",
    } <= tables


def test_cve_cache_keyed_by_cve_id(session):
    session.add(CveCache(cve_id="CVE-2021-44228", kev=True))
    session.commit()
    assert session.query(CveCache).one().kev is True


def test_run_lessons_schema_only_no_mvp_writes(session):
    # Schema exists (spec §7.3 foundation); nothing in MVP writes to it.
    assert session.query(RunLesson).count() == 0
