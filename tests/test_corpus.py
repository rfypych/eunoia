"""T7: real-corpus recall measurement (same method as 19 Nov 2026).

The 19 Nov 2026 measurement ran the real-queries set through
``eunoia.search.search`` (read-only) and reported recall@10 + p50/p95
split by pre-test / mid-test. This module tests the reusable version
of that method: :func:`measure_real_recall` + :func:`validate_real_queries`
in ``eunoia.golden``. The queries file itself
(``docs/golden/real-queries-500.json``) is data, built from the 500-row
corpus and validated by :func:`validate_real_queries` before any
measurement is trusted.
"""

from __future__ import annotations

import re
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.golden import (
    load_corpus,
    measure_real_recall,
    seed_golden_corpus,
    validate_real_queries,
)
from eunoia.models import Base, Writeup

TEST_DATABASE_URL = "postgresql+psycopg://eunoia@127.0.0.1:5432/eunoia_test"

_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder (same vocabulary as test_golden)."""

    def encode(self, texts):
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


@pytest.fixture()
def golden(session, encoder):
    return seed_golden_corpus(session, model=encoder)


def _queries_from_golden():
    """Two real-queries-shaped queries over the synthetic golden
    corpus: one pre-test (class SQLi), one mid-test (evidence text).
    Expected ids are read from the corpus itself, never invented."""
    corpus = load_corpus()["writeups"]
    sqli = [f"w_{uuid.UUID(w['id']).hex}" for w in corpus
            if w["vuln_class"] == "SQLi" and w["status"] == "active"
            and w["language"] == "en"]
    assert sqli, "golden corpus must carry servable SQLi rows"
    return [
        {"id": "tq01", "mode": "pre_test", "vuln_class": "SQLi",
         "expected_writeup_ids": sqli},
        {"id": "tq02", "mode": "mid_test",
         "evidence_pattern": "blind SQL injection",
         "expected_writeup_ids": sqli[:1]},
    ]


def test_t7_validate_real_queries_accepts_real_rows(session, encoder, golden):
    assert validate_real_queries(_queries_from_golden(), session) == []


def test_t7_validate_real_queries_rejects_missing_and_quarantined(
        session, encoder, golden):
    corpus = load_corpus()["writeups"]
    retracted = next(w["id"] for w in corpus if w["status"] != "active")
    errors = validate_real_queries([
        {"id": "bad1", "mode": "pre_test", "vuln_class": "SQLi",
         "expected_writeup_ids": ["w_00000000000000000000000000000000"]},
        {"id": "bad2", "mode": "pre_test", "vuln_class": "SQLi",
         "expected_writeup_ids": [f"w_{uuid.UUID(retracted).hex}"]},
    ], session)
    assert len(errors) == 2
    assert "bad1" in errors[0] and "bad2" in errors[1]


def test_t7_measure_real_recall_reports_split_numbers(
        session, encoder, golden):
    report = measure_real_recall(
        session=session, model=encoder, queries=_queries_from_golden())
    assert report.corpus_size == session.query(Writeup).filter_by(
        status="active").count()
    assert report.pre_test["n"] == 1
    assert report.mid_test["n"] == 1
    assert 0.0 <= report.recall_at_10 <= 1.0
    assert report.p50_ms >= 0.0 and report.p95_ms >= report.p50_ms
    assert len(report.per_query) == 2
