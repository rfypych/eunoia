"""Task 15: golden set (~50 queries) + recall@10 + latency measurement.

The golden set is built from the real MVP corpus: ``docs/golden/corpus.json``
seeds 26 writeups (24 servable + 1 retracted + 1 non-English) with
deterministic UUIDv7 ids, so the same ``w_...`` api ids exist in the dev
DB (via ``scripts/measure_recall.py --seed``) and in the test DB (via the
``golden`` fixture here). Every golden query names expected writeup ids
that exist in that corpus — nothing is invented.

No invented pass threshold: ``measure_recall`` reports the measured
recall@10 and latencies as-is. The tests assert structure (fields,
ranges, expected ids exist, excluded rows never served) and the
implemented ``_stack_match`` 0.7-band reading — never a recall bar.
The pass bar is decided after the first measurement (spec §8).

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_search.py). The embedding model is a
keyword stub encoder — no test downloads weights.
"""

from __future__ import annotations

import json
import re
import uuid
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.golden import (
    Report,
    load_corpus,
    load_expected,
    load_queries,
    measure_recall,
    seed_golden_corpus,
)
from eunoia.models import Base, CveCache, Writeup
from eunoia.search import search

TEST_DATABASE_URL = "postgresql+psycopg://eunoia@127.0.0.1:5432/eunoia_test"

# Same vocabulary as tests/test_search.py: cosine similarity is term
# overlap over these words, so the stub encoder is deterministic.
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


@pytest.fixture()
def golden(session, encoder):
    return seed_golden_corpus(session, model=encoder)


# --- brief verbatim test ---------------------------------------------------


def test_golden_set_has_50_queries():
    # Repo-root relative (final review triage, Task 15): the test
    # must pass from any working directory, not only the repo root.
    repo = Path(__file__).resolve().parent.parent
    qs = json.loads((repo / "docs" / "golden" / "queries.json").read_text())
    assert len(qs) >= 50
    assert all("expected_writeup_ids" in q for q in qs)


# --- golden-set integrity --------------------------------------------------


def test_expected_json_agrees_with_queries():
    qs = load_queries()
    expected = load_expected()
    assert set(expected) == {q["id"] for q in qs}
    for q in qs:
        assert expected[q["id"]] == q["expected_writeup_ids"]


def test_golden_expected_ids_exist_in_corpus(session, encoder, golden):
    qs = load_queries()
    ids = {
        w.api_id
        for w in session.query(Writeup)
        .filter(Writeup.status == "active").all()
    }
    assert golden["seeded"] >= 24
    for q in qs:
        assert q["expected_writeup_ids"], q["id"]
        for wid in q["expected_writeup_ids"]:
            assert wid in ids, (q["id"], wid)


def test_reseed_updates_changed_fields(session, encoder, golden):
    """Final review triage, Task 15: editing corpus.json after a
    first seed must update the row on re-seed, not leave it stale."""
    first = session.query(Writeup).order_by(Writeup.id).first()
    first.title = "Stale title that corpus.json no longer has"
    session.flush()
    result = seed_golden_corpus(session, model=encoder)
    assert result["updated"] >= 1
    refreshed = session.get(Writeup, first.id)
    assert refreshed.title != "Stale title that corpus.json no longer has"


def test_excluded_rows_never_served(session, encoder, golden):
    # Final review triage, Task 15: assert by api id, not by title
    # substring — a title substring check would pass even if the
    # wrong row were served under a different title.
    corpus = load_corpus()
    excluded_ids = {
        f"w_{uuid.UUID(w['id']).hex}"
        for w in corpus["writeups"]
        if w["status"] != "active" or w["language"] != "en"
    }
    assert excluded_ids, "corpus must carry excluded rows to test"
    for q in load_queries():
        results = search(q, limit=10, session=session, model=encoder)
        returned = {r.writeup_id for r in results}
        assert not (returned & excluded_ids), q["id"]


# --- measurement -----------------------------------------------------------


def test_measure_recall_reports_honest_numbers(session, encoder, golden):
    report = measure_recall(session=session, model=encoder)
    assert isinstance(report, Report)
    assert 0.0 <= report.recall_at_10 <= 1.0
    assert report.p50_ms >= 0 and report.p95_ms >= 0
    assert len(report.per_query) == len(load_queries())
    for row in report.per_query:
        assert 0.0 <= row.recall <= 1.0
        assert row.latency_ms >= 0
        assert set(row.found_ids) <= set(row.expected_ids)
        assert set(row.returned_ids) >= set(row.found_ids)
    # No invented pass threshold: the value is reported, not asserted.
    assert report.pre_test["n"] + report.mid_test["n"] == len(load_queries())


def test_stack_match_07_band_reading(session, encoder, golden):
    """Validate the IMPLEMENTED 0.7-band reading (Task 9 deferred minor).

    ``search._stack_match`` assigns 0.7 whenever the query carries no
    version ("same product, version not exactly known") — NOT the
    spec's range-based reading (0.7 = "same product, version in
    affected range"), because MVP has no OSV data to establish affected
    ranges. The golden set validates the implemented reading; the
    range-based reading is untestable in MVP and recorded as such in
    the measurement report.
    """
    results = search({"tech": ["spring-boot"]}, limit=10,
                     session=session, model=encoder)
    ssrf = next(r for r in results if "PDF parser" in r.title)
    assert ssrf.score_breakdown["stack_match"] == 0.7

    # Version-carrying query: a writeup whose title names the same
    # version scores 1.0 (the classifier fills the CPE version slot
    # from the version next to the technology mention); a writeup
    # naming no version scores 0.4, not 1.0 and not 0.7.
    versioned = search({"tech": ["spring-boot"], "version": "3.2.0"},
                       limit=10, session=session, model=encoder)
    ssrf_v = next(r for r in versioned if "PDF parser" in r.title)
    assert ssrf_v.score_breakdown["stack_match"] == 1.0
    idor_v = next(r for r in versioned if "Actuator" in r.title)
    assert idor_v.score_breakdown["stack_match"] == 0.4


def test_harness_run_counts_queries_per_run(session, encoder, golden):
    """Queries per run (§9 Q8): the harness run itself is measurable."""
    from eunoia.harness.loop import run_loop
    from eunoia.harness.state import Fingerprint
    from eunoia.safety.scope import Scope

    report = run_loop(
        scope=Scope(allowlist=["app.lab.internal"]),
        lab_target="https://app.lab.internal",
        session=session, model=encoder,
        fingerprinter=lambda target: [
            Fingerprint(technology="spring-boot", version="3.2.0",
                        confidence=0.9, bukti=("Server header",)),
        ],
    )
    queries_per_run = len(report.lookup1_calls) + len(report.lookup2_calls)
    assert queries_per_run >= 1
    assert report.retrieval_tokens <= 20_000


def test_every_cve_in_corpus_has_complete_cve_cache_row(session, encoder, golden):
    """DoD 2 (Task 16): every CVE in MVP writeups has cvss_score,
    cwe_ids, and a KEV flag in cve_cache."""
    cves = {w["cve_id"] for w in load_corpus()["writeups"] if w["cve_id"]}
    assert cves, "corpus has no CVEs at all"
    for cve_id in sorted(cves):
        row = session.get(CveCache, cve_id)
        assert row is not None, f"{cve_id} has no cve_cache row"
        assert row.cvss_score is not None, f"{cve_id} has no cvss_score"
        assert row.cwe_ids, f"{cve_id} has no cwe_ids"
        assert row.kev is not None, f"{cve_id} has no KEV flag"
