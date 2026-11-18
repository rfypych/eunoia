"""Task 14: lab-only reference harness — 10-step loop (§5.8, §5.10).

Tests run against a local self-owned Spring lab app fixture (seeded
test-DB corpus + stub encoder + stub fingerprint/probe adapters).
No live target is ever touched: the default fingerprinter returns no
fingerprint and the default probe adapter is a read-only stub.
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
from eunoia.harness.budget import (
    COMPACT_LINE,
    LOOKUP1_LIMIT,
    LOOKUP2_LIMIT,
    PRUNE_LINE,
    RETRIEVAL_CAP,
    BudgetExceeded,
    TokenBudget,
    estimate_tokens,
)
from eunoia.harness.loop import (
    KillSwitchStopped,
    Observation,
    run_loop,
)
from eunoia.harness.prove import (
    prove_candidate,
    sanitize_evidence,
)
from eunoia.harness.state import Fingerprint, Hypothesis, RunState
from eunoia.models import Base, Writeup, WriteupVuln
from eunoia.safety.scope import Scope, ScopeBlocked

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)

_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder (same pattern as test_search.py)."""

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


def _writeup(session, *, title, excerpt, program, vuln_class, cwe,
             severity=None, bounty_verified=False, bounty_amount=None):
    url = f"https://example.com/reports/{uuid.uuid4().hex[:12]}"
    published = NOW - timedelta(days=5)
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        title=title,
        excerpt=excerpt,
        language="en",
        status="active",
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


@pytest.fixture()
def lab(session, encoder, monkeypatch):
    """Seeded lab corpus + patched no-session search path.

    The verbatim brief tests call ``run_loop`` with no session/model,
    so the fixture patches the search module's own-session path to
    the test database and the stub encoder, and patches the harness
    default fingerprinter to the lab's known fingerprint.
    """
    ssrf = _writeup(
        session, title="SSRF via PDF parser in Spring Boot 3.2.0",
        excerpt="SSRF via PDF parser in a Spring Boot application",
        program="Example Spring Boot app", vuln_class="SSRF",
        cwe="CWE-918", severity="critical",
        bounty_verified=True, bounty_amount=5000,
    )
    embed_writeup(ssrf.id, session=session, model=encoder)
    xss = _writeup(
        session, title="Stored XSS in Spring Framework views",
        excerpt="Stored XSS via unescaped model attributes in Spring MVC",
        program="Spring Framework demo", vuln_class="XSS", cwe="CWE-79",
        severity="high",
    )
    embed_writeup(xss.id, session=session, model=encoder)
    rce = _writeup(
        session, title="RCE in Apache Tomcat 10.1 request handling",
        excerpt="Remote code execution in Tomcat 10.1 via deserialization",
        program="Apache Tomcat", vuln_class="RCE", cwe="CWE-502",
        severity="critical",
        bounty_verified=True, bounty_amount=1000,
    )
    embed_writeup(rce.id, session=session, model=encoder)
    session.commit()

    monkeypatch.setattr(
        "eunoia.search.get_settings",
        lambda **kw: get_settings(DATABASE_URL=TEST_DATABASE_URL),
    )
    monkeypatch.setattr(
        "eunoia.harness.loop.get_settings",
        lambda **kw: get_settings(DATABASE_URL=TEST_DATABASE_URL),
    )
    monkeypatch.setattr("eunoia.search.get_model", lambda: encoder)
    monkeypatch.setattr(
        "eunoia.harness.loop._default_fingerprint",
        lambda target: [
            Fingerprint(technology="spring-boot", version="3.2.0",
                        confidence=0.9,
                        bukti=["header X-Powered-By: Spring Boot",
                               "path /actuator/health"]),
            Fingerprint(technology="tomcat", version="10.1.0",
                        confidence=0.8,
                        bukti=["header Server: Apache-Coyote/1.1"]),
        ],
    )
    return {
        "scope": Scope(allowlist=["app.lab.internal"]),
        "url": "https://app.lab.internal",
        "ssrf": ssrf,
        "xss": xss,
        "rce": rce,
    }


# --- verbatim brief tests ---------------------------------------------------

def test_scope_gate_blocks_out_of_scope_target(lab):
    with pytest.raises(ScopeBlocked):
        run_loop(scope=Scope(allowlist=["lab.internal"]),
                 lab_target="https://example.com")


def test_lookup2_triggered_after_3_failed_probes(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"],
                      probes_fail=3)
    assert len(report.lookup2_calls) >= 1
    assert all(len(c.results) <= 3 for c in report.lookup2_calls)


# --- step 0 / step 1: scope gate, kill switch, fingerprint -----------------

def test_no_lookup_before_minimal_fingerprint(lab, monkeypatch):
    monkeypatch.setattr("eunoia.harness.loop._default_fingerprint",
                        lambda target: [])
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    assert report.status == "stopped_no_fingerprint"
    assert report.lookup1_calls == [] and report.lookup2_calls == []


def test_kill_switch_stops_run_before_any_lookup(lab):
    with pytest.raises(KillSwitchStopped):
        run_loop(scope=lab["scope"], lab_target=lab["url"],
                 kill_switch=lambda: True)


def test_fingerprint_carries_confidence_and_bukti(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    assert report.fingerprint
    assert all(f.confidence > 0 and f.bukti for f in report.fingerprint)


# --- step 2: Lookup #1 ------------------------------------------------------

def test_lookup1_one_query_per_technology_limit_5(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    assert len(report.lookup1_calls) == 2  # spring-boot + tomcat
    assert all(len(c.results) <= LOOKUP1_LIMIT
               for c in report.lookup1_calls)
    assert all(c.limit == LOOKUP1_LIMIT for c in report.lookup1_calls)


def test_lookup1_results_become_hypotheses(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    assert report.hypotheses
    assert {h.status for h in report.hypotheses} <= {
        "open", "testing", "confirmed", "debunked"}


# --- seen-ids / Lookup #2 cache / re-query cap ------------------------------

def test_seen_ids_never_re_read(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"],
                      probes_fail=3)
    seen: set[str] = set()
    for call in report.lookup1_calls + report.lookup2_calls:
        ids = [r.writeup_id for r in call.results]
        assert not (set(ids) & seen), "an id was returned twice in one run"
        seen.update(ids)


def test_lookup2_max_two_requeries_per_hypothesis(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"],
                      probes_fail=100)
    assert report.lookup2_calls
    per_hyp: dict[str, int] = {}
    for call in report.lookup2_calls:
        per_hyp[call.hypothesis_id] = per_hyp.get(call.hypothesis_id, 0) + 1
    assert all(n <= 2 for n in per_hyp.values())


def test_same_normalized_lookup2_query_served_from_cache(lab):
    state = RunState()
    first = state.cached_lookup("spring-boot|ssrf|pdf")
    assert first is None
    state.cache_lookup("spring-boot|ssrf|pdf", ["w_01"])
    assert state.cached_lookup("spring-boot|ssrf|pdf") == ["w_01"]
    assert state.cached_lookup("spring-boot|ssrf|other") is None


# --- step 8: Prove ----------------------------------------------------------

def _hypothesis(**kw):
    base = dict(id="h1", writeup_id="w_01", title="SSRF via PDF parser",
                technique="SSRF", target="https://app.lab.internal",
                status="open", priority=1)
    base.update(kw)
    return Hypothesis(**base)


def test_prove_confirmed_with_signal_and_reproduction_steps():
    hyp = _hypothesis()
    obs = [Observation(status=200, body="fetched internal metadata",
                       signal=True)]
    finding = prove_candidate(hyp, obs, ["GET /pdf?url=http://169.254.169.254"])
    assert finding.status == "confirmed"
    assert finding.reproduction_steps
    assert finding.evidence


def test_prove_unverified_without_reproduction_steps():
    hyp = _hypothesis()
    obs = [Observation(status=200, body="odd error", signal=True)]
    finding = prove_candidate(hyp, obs, [])
    assert finding.status == "unverified"


def test_prove_debunked_hypothesis_stays_debunked():
    hyp = _hypothesis(status="debunked")
    obs = [Observation(status=200, body="normal response", signal=False)]
    finding = prove_candidate(hyp, obs, ["GET /pdf?url=http://example.com"])
    assert finding.status == "debunked"


def test_prove_strips_secrets_from_evidence():
    hyp = _hypothesis()
    obs = [Observation(status=200, body="token=ghp_abcdefghij0123456789"
                       "abcdefghij0123456789", signal=True)]
    finding = prove_candidate(
        hyp, obs, ["GET /pdf?url=http://169.254.169.254"])
    assert finding.status == "confirmed"
    assert "ghp_abcdefghij0123456789" not in " ".join(finding.evidence)
    assert any("REDACTED" in e for e in finding.evidence)


def test_sanitize_evidence_redacts_secrets():
    redacted = sanitize_evidence(
        "leaked AKIAIOSFODNN7EXAMPLE in the response body")
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted
    assert "REDACTED" in redacted


# --- step 9: report + human review ------------------------------------------

def test_report_requires_human_review_for_material_findings(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    material = [f for f in report.findings if f.status == "confirmed"]
    if material:
        assert report.human_review_required is True
    assert report.audit, "run must carry a complete audit trail"


def test_scratchpad_is_structured_not_full_text(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    scratch = report.scratchpad
    assert isinstance(scratch, dict)
    assert "hypotheses" in scratch and "fingerprint" in scratch
    blob = str(scratch)
    assert "SSRF via PDF parser in a Spring Boot application" not in blob


# --- token budget (§5.10) ----------------------------------------------------

def test_budget_retrieval_cap_enforced():
    budget = TokenBudget()
    budget.record_retrieval(RETRIEVAL_CAP)
    with pytest.raises(BudgetExceeded):
        budget.record_retrieval(1)


def test_budget_action_lines():
    budget = TokenBudget()
    assert budget.action() == "ok"
    budget.record_state(PRUNE_LINE)
    assert budget.action() == "prune"
    budget.record_state(COMPACT_LINE - PRUNE_LINE)
    assert budget.action() == "compact"


def test_estimate_tokens_is_deterministic():
    assert estimate_tokens("abcd") == 1
    assert estimate_tokens("abcdefgh") == 2
    assert estimate_tokens("x") == 1


def test_run_never_exceeds_retrieval_cap(lab):
    report = run_loop(scope=lab["scope"], lab_target=lab["url"],
                      probes_fail=100)
    assert report.retrieval_tokens <= RETRIEVAL_CAP


def test_state_compact_drops_raw_tool_output():
    state = RunState()
    state.record_observation("h1", "x" * 4000)
    state.record_observation("h1", "y" * 4000)
    state.compact()
    assert state.compacted is True
    assert all(len(o) <= 120 for o in state.observations["h1"])


def test_redirect_outside_allowlist_blocked_in_run(lab):
    """DoD 6 (Task 16): a probe that redirects outside the allowlist
    is blocked inside the run, not followed, and the observation is
    treated as no-signal."""
    calls = {"n": 0}

    def _probe(hypothesis, target):
        calls["n"] += 1
        if calls["n"] == 1:
            return Observation(status=302, body="redirect",
                               signal=False,
                               redirect_url="https://evil.example/x")
        return Observation(status=200, body="signal", signal=True)

    report = run_loop(scope=lab["scope"], lab_target=lab["url"],
                      probe_adapter=_probe)
    blocked = [a for a in report.audit if a["event"] == "redirect_blocked"]
    assert len(blocked) == 1
    assert blocked[0]["detail"]["redirect_url"] == "https://evil.example/x"


def test_run_report_records_budget_before_threshold(lab):
    """DoD 7 (Task 16): the run records that it finished before the
    65% compaction line (retrieval <= 20k), not just that it stayed
    under the cap."""
    report = run_loop(scope=lab["scope"], lab_target=lab["url"])
    assert report.coverage["retrieval_tokens"] <= 20_000
    assert report.coverage["budget_action"] == "ok"
    assert report.coverage["window_used_pct"] < 65
