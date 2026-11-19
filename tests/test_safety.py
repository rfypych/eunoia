"""Task 13: Safety gate — Scope Gate, approval tiers, audit, takedown
(spec §6, §5.8 step 0).

DB tests run against the dedicated ``eunoia_test`` database (same
fixture pattern as tests/test_skills.py).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.models import Base, Takedown, Writeup, WriteupEvent, WriteupVuln
from eunoia.safety.approvals import (
    Action,
    ActionKind,
    ApprovalGate,
    HumanApproval,
    JudgeConfig,
    JudgeVerdict,
    StubJudge,
)
from eunoia.safety.audit import APPEND_ONLY_TRIGGER_SQL, audit_append
from eunoia.safety.quality import detect_language, quality_gate
from eunoia.safety.scope import Scope, ScopeBlocked, ScopeGate
from eunoia.safety.secrets_scan import (
    Finding,
    SecretFoundError,
    contains_secret,
    scan_secrets,
)
from eunoia.safety.takedown import (
    DMCA_AGENT_EMAIL,
    DMCA_AGENT_NAME,
    TAKEDOWN_STUB,
    acknowledge_by,
    apply_author_removal,
    apply_takedown,
    stub_by,
    validate_notice,
)
from eunoia.skills import get_skill_text

TEST_DATABASE_URL = "postgresql+psycopg://eunoia@localhost/eunoia_test"

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


def _writeup(session, *, title="SSRF via PDF parser", excerpt=None,
             status="active", days_ago=5):
    """Insert one writeup; returns the Writeup."""
    url = f"https://example.com/reports/{uuid.uuid4().hex[:12]}"
    published = NOW - timedelta(days=days_ago)
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        title=title,
        excerpt=excerpt,
        author_name="Researcher",
        language="en",
        status=status,
        published_at=published,
        disclosed_at=published,
        fetched_at=NOW,
        last_seen_at=NOW,
        content_hash=url_hash(url),
    )
    session.add(w)
    session.flush()
    return w


# --- Scope Gate (brief verbatim tests) ---

def test_scope_gate_blocks_redirect_outside_allowlist():
    scope = Scope(allowlist=["lab.example.internal"], denylist=[])
    assert ScopeGate.check("https://evil.example/x", scope) is False


def test_scope_gate_allows_allowlisted_host():
    scope = Scope(allowlist=["lab.example.internal"], denylist=[])
    assert ScopeGate.check("https://lab.example.internal/app", scope) is True


def test_scope_gate_default_deny_empty_allowlist():
    scope = Scope(allowlist=[], denylist=[])
    assert ScopeGate.check("https://lab.example.internal/app", scope) is False


def test_scope_gate_denylist_beats_allowlist():
    scope = Scope(allowlist=["example.internal"],
                  denylist=["bad.example.internal"])
    assert ScopeGate.check("https://bad.example.internal/x", scope) is False
    assert ScopeGate.check("https://good.example.internal/x", scope) is True


def test_scope_gate_subdomain_of_allowlisted_domain():
    scope = Scope(allowlist=["example.internal"], denylist=[])
    assert ScopeGate.check("https://app.example.internal/x", scope) is True
    # Suffix tricks must not match: notexample.internal is a different host.
    assert ScopeGate.check("https://notexample.internal/x", scope) is False


def test_scope_gate_bare_host_and_port():
    scope = Scope(allowlist=["lab.example.internal"], denylist=[])
    assert ScopeGate.check("lab.example.internal", scope) is True
    assert ScopeGate.check("lab.example.internal:8443/path", scope) is True
    assert ScopeGate.check("not-a-url [[[", scope) is False


def test_scope_gate_redirect_target_checked():
    scope = Scope(allowlist=["lab.example.internal"], denylist=[])
    assert ScopeGate.check_redirect(
        "https://lab.example.internal/a", "https://lab.example.internal/b",
        scope) is True
    assert ScopeGate.check_redirect(
        "https://lab.example.internal/a", "https://evil.example/x",
        scope) is False


def test_scope_gate_require_raises():
    scope = Scope(allowlist=["lab.example.internal"], denylist=[])
    with pytest.raises(ScopeBlocked):
        ScopeGate.require("https://evil.example/x", scope)
    assert ScopeGate.require("https://lab.example.internal/x", scope) is True


# --- Secret scan (brief verbatim test) ---

def test_secret_scan_blocks_token_in_excerpt():
    assert scan_secrets("token: ghp_abcdefghij1234567890abcdefghij12") != []


def test_secret_scan_patterns():
    assert scan_secrets("key AKIAIOSFODNN7EXAMPLE")[0].pattern == "aws_access_key"
    assert scan_secrets("-----BEGIN PRIVATE KEY-----\nMIIE")[0].pattern == "private_key"
    assert scan_secrets("xoxb-123456789012-1234567890123-AbCdEf")[0].pattern == "slack_token"
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert scan_secrets(jwt)[0].pattern == "jwt"
    assert scan_secrets("api_key = 'sk_live_abcdefghij1234567890'")[0].pattern in (
        "stripe_live_key", "generic_credential_assignment")


def test_secret_scan_clean_text_is_empty():
    assert scan_secrets("SSRF via an unvalidated redirect in a PDF parser.") == []
    assert scan_secrets("") == []
    assert scan_secrets(None) == []
    assert contains_secret("nothing sensitive here") is False
    assert contains_secret("token: ghp_abcdefghij1234567890abcdefghij12") is True


def test_secret_scan_finding_never_contains_the_secret():
    secret = "ghp_abcdefghij1234567890abcdefghij12"
    findings = scan_secrets(f"token: {secret}")
    assert findings != []
    assert isinstance(findings[0], Finding)
    for f in findings:
        assert secret not in f.preview
        assert secret not in repr(f)


def test_skill_generation_refuses_secret_in_title(session):
    w = _writeup(session,
                 title="SSRF with token ghp_abcdefghij1234567890abcdefghij12")
    session.flush()
    with pytest.raises(SecretFoundError, match="secret"):
        get_skill_text(w.api_id, session=session)


def test_secret_found_error_is_not_a_value_error():
    # The refusal must be a distinct type: the R10 status gate raises
    # ValueError, which the serving layers map to 410 Gone. If the
    # secret-scan refusal were a ValueError too, a safety refusal
    # would be misreported as a takedown.
    assert not issubclass(SecretFoundError, ValueError)


# --- Audit (append-only) ---

def test_audit_append_writes_event(session):
    w = _writeup(session)
    event = audit_append(session, writeup_id=w.id, event="created",
                         actor="poller", detail={"source": "hackerone"})
    session.flush()
    assert isinstance(event, WriteupEvent)
    assert event.event == "created"
    assert event.actor == "poller"
    assert event.detail == {"source": "hackerone"}
    assert session.query(WriteupEvent).count() == 1


def test_audit_append_rejects_unknown_event(session):
    w = _writeup(session)
    with pytest.raises(ValueError, match="unknown audit event"):
        audit_append(session, writeup_id=w.id, event="deleted",
                     actor="poller")


def test_audit_log_is_append_only_at_the_database(session):
    engine = session.get_bind()
    with engine.begin() as conn:
        conn.execute(text(APPEND_ONLY_TRIGGER_SQL))
    w = _writeup(session)
    audit_append(session, writeup_id=w.id, event="created", actor="poller")
    session.flush()
    # Commit the row first: a later rollback (after the failed UPDATE)
    # must not wipe the row the DELETE check needs.
    session.commit()
    with pytest.raises(DBAPIError):
        session.execute(
            text("UPDATE writeup_events SET actor = 'mallory'"))
        session.flush()
    session.rollback()
    with pytest.raises(DBAPIError):
        session.execute(text("DELETE FROM writeup_events"))
        session.flush()
    session.rollback()
    assert session.query(WriteupEvent).count() == 1


# --- Approval tiers + LLM-as-judge ---

def _judge_config():
    return JudgeConfig(model="judge-model-1", prompt_version="judge-v1",
                       planner_model="planner-model-1")


def test_autonomous_tier_needs_only_scope_gate():
    action = Action(kind=ActionKind.PASSIVE_RECON,
                    target="lab.example.internal")
    decision = ApprovalGate.decide(action, scope_ok=True)
    assert decision.allowed is True
    assert decision.tier == "autonomous"


def test_autonomous_tier_blocked_out_of_scope():
    action = Action(kind=ActionKind.REGISTRY_QUERY, target="evil.example")
    decision = ApprovalGate.decide(action, scope_ok=False)
    assert decision.allowed is False


def test_exploit_needs_judge_pass_and_human_approval():
    action = Action(kind=ActionKind.EXPLOIT, target="lab.example.internal")
    # Neither judge nor human: denied.
    assert ApprovalGate.decide(action, scope_ok=True).allowed is False
    # Judge pass alone: still denied.
    verdict = StubJudge(passed=True).review(action, _judge_config())
    assert ApprovalGate.decide(action, scope_ok=True,
                               judge_verdict=verdict).allowed is False
    # Judge pass + recorded human approval: allowed.
    human = HumanApproval(approver="operator", at=NOW, note="lab-only")
    decision = ApprovalGate.decide(action, scope_ok=True,
                                   judge_verdict=verdict, human_approval=human)
    assert decision.allowed is True
    assert decision.judge_model == "judge-model-1"


def test_exploit_denied_when_judge_fails_even_with_human_approval():
    action = Action(kind=ActionKind.EXPLOIT, target="lab.example.internal")
    verdict = StubJudge(passed=False, reason="too risky").review(
        action, _judge_config())
    human = HumanApproval(approver="operator", at=NOW)
    decision = ApprovalGate.decide(action, scope_ok=True,
                                   judge_verdict=verdict, human_approval=human)
    assert decision.allowed is False


def test_unapprovable_tier_is_blocked_in_code():
    verdict = StubJudge(passed=True).review(
        Action(kind=ActionKind.DESTRUCTIVE, target="lab.example.internal"),
        _judge_config())
    human = HumanApproval(approver="operator", at=NOW)
    for kind in (ActionKind.DESTRUCTIVE, ActionKind.EXFILTRATION,
                 ActionKind.OUT_OF_SCOPE, ActionKind.NON_CONSENSUAL):
        action = Action(kind=kind, target="lab.example.internal")
        decision = ApprovalGate.decide(action, scope_ok=True,
                                       judge_verdict=verdict,
                                       human_approval=human)
        assert decision.allowed is False, kind
        assert decision.tier == "unapprovable"


def test_judge_must_not_be_the_planner_without_a_written_note():
    with pytest.raises(ValueError, match="judge.*planner"):
        JudgeConfig(model="same-model", prompt_version="judge-v1",
                    planner_model="same-model")
    cfg = JudgeConfig(model="same-model", prompt_version="judge-v1",
                      planner_model="same-model",
                      acknowledge_same_model=True)
    assert cfg.acknowledge_same_model is True
    verdict = StubJudge(passed=True).review(
        Action(kind=ActionKind.EXPLOIT, target="lab.example.internal"), cfg)
    assert verdict.model == "same-model"


def test_judge_verdict_records_model_and_prompt():
    verdict = JudgeVerdict(passed=True, reason="read-only probe",
                           model="judge-model-1", prompt_version="judge-v1")
    assert verdict.model == "judge-model-1"
    assert verdict.prompt_version == "judge-v1"


def test_judge_accepts_newline_separated_verdict():
    """Final review triage, Task 13: the verdict used to be parsed
    with partition(" "), so "APPROVE\\n<reason>" failed closed as
    DENY. Splitting on any whitespace makes it a legitimate APPROVE."""
    from eunoia.safety.approvals import ActionKind, LLMJudge

    judge = LLMJudge(lambda prompt: "APPROVE\nread-only probe, in scope")
    verdict = judge.review(
        Action(kind=ActionKind.EXPLOIT, target="lab.example.internal"),
        _judge_config())
    assert verdict.passed is True
    assert verdict.reason == "read-only probe, in scope"


def test_quality_gate_unknown_class_goes_to_review():
    """Final review triage, Task 13: the "mapped" check used to
    accept any non-empty string. An unknown class is now treated
    like unclassified — review queue, never "pass"."""
    result = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="Weird bug", author_name="Researcher",
        published_at=NOW, vuln_class="banana",
        excerpt="Something odd happened.", language="en",
        url_checker=_ok_url)
    assert result.vuln_class == "unclassified"
    assert result.needs_review is True
    assert result.checks["vuln_class"] == "review"


# --- Takedown ---

def test_dmca_agent_is_named():
    assert DMCA_AGENT_NAME
    assert "@" in DMCA_AGENT_EMAIL


def test_validate_notice_requires_all_six_elements():
    notice = {"signature": "s", "work_identification": "w",
              "material_identification": "https://example.com/reports/1",
              "contact": "c@example.com",
              "good_faith_statement": "good faith",
              "accuracy_statement": "under penalty of perjury"}
    assert validate_notice(notice) == []
    missing = validate_notice({"signature": "s"})
    assert len(missing) == 5
    assert "material_identification" in missing


def test_working_day_deadlines_skip_weekends():
    # 2026-11-20 is a Friday.
    friday = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)
    assert acknowledge_by(friday).date().isoformat() == "2026-11-24"  # Tue
    assert stub_by(friday).date().isoformat() == "2026-11-27"  # Fri


def test_apply_takedown_stubs_record_and_logs(session):
    w = _writeup(session, excerpt="Original excerpt with technique detail.")
    session.flush()
    row = apply_takedown(session, w, requester="Copyright Owner",
                         notice_ref="DMCA-2026-001",
                         reason="copyrighted material",
                         received_at=datetime(2026, 11, 20, 10, 0,
                                              tzinfo=timezone.utc))
    session.flush()
    assert isinstance(row, Takedown)
    assert w.status == "takedown"
    assert w.excerpt == TAKEDOWN_STUB
    assert "Original excerpt" not in (w.excerpt or "")
    assert w.takedown_at is not None
    assert session.query(Takedown).count() == 1
    events = session.query(WriteupEvent).filter_by(writeup_id=w.id).all()
    assert [e.event for e in events] == ["takedown"]
    assert events[0].detail["notice_ref"] == "DMCA-2026-001"
    # A taken-down writeup is not served as a skill (Ruling R10).
    with pytest.raises(ValueError):
        get_skill_text(w.api_id, session=session)


def test_apply_author_removal_honored_the_same_way(session):
    w = _writeup(session)
    session.flush()
    apply_author_removal(session, w, requester="Researcher",
                         reason="author asked for removal")
    session.flush()
    assert w.status == "takedown"
    assert w.excerpt == TAKEDOWN_STUB
    assert session.query(Takedown).count() == 1


# --- Quality gate ---

def _ok_url(url):
    return True


def test_quality_gate_passes_clean_record():
    result = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="SSRF via PDF parser", author_name="Researcher",
        published_at=NOW, vuln_class="ssrf",
        excerpt="Unvalidated redirect in a PDF parser.",
        language="en", url_checker=_ok_url)
    assert result.passed is True
    assert result.needs_review is False
    assert result.vuln_class == "ssrf"


def test_quality_gate_blocks_secret_in_excerpt():
    result = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="SSRF via PDF parser", author_name="Researcher",
        published_at=NOW, vuln_class="ssrf",
        excerpt="token: ghp_abcdefghij1234567890abcdefghij12",
        language="en", url_checker=_ok_url)
    assert result.passed is False
    assert result.checks["secrets"] == "fail"


def test_quality_gate_unmapped_class_goes_to_review_queue():
    result = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="Weird bug", author_name="Researcher",
        published_at=NOW, vuln_class=None,
        excerpt="Something odd happened.", language="en",
        url_checker=_ok_url)
    assert result.vuln_class == "unclassified"
    assert result.needs_review is True
    assert result.checks["vuln_class"] == "review"


def test_quality_gate_requires_resolvable_url_and_fields():
    no_checker = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="SSRF", author_name="Researcher", published_at=NOW,
        vuln_class="ssrf", excerpt="ok", language="en", url_checker=None)
    assert no_checker.passed is False
    assert no_checker.checks["canonical_url"] == "skipped"

    dead = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="SSRF", author_name="Researcher", published_at=NOW,
        vuln_class="ssrf", excerpt="ok", language="en",
        url_checker=lambda url: False)
    assert dead.passed is False
    assert dead.checks["canonical_url"] == "fail"

    missing = quality_gate(
        canonical_url="https://example.com/reports/1",
        title="", author_name=None, published_at=None,
        vuln_class="ssrf", excerpt="ok", language="en",
        url_checker=_ok_url)
    assert missing.passed is False
    assert missing.checks["fields"] == "fail"


def test_detect_language():
    assert detect_language("SSRF via an unvalidated redirect in the parser",
                           "The server fetched the URL.") == "en"
    assert detect_language("", "") is None
