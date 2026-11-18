"""Reference harness: the 10-step agent loop, lab-only (spec §5.8, §5.10).

This is a REFERENCE implementation, not a pentest agent and not a
production harness. It runs against targets the operator owns (own
Spring lab app, DVWA, own lab), and it never executes exploits:

* probes are safe read probes only (``ActionKind.READ_PROBE``,
  autonomous tier — Scope Gate only, no exploit/credential/state
  action is ever issued by this module);
* the default probe adapter is a stub: no network traffic at all.
  A real lab-only adapter must be injected explicitly by the caller;
* every execution call re-checks the Scope Gate, including redirects;
* the kill switch is checked at step 0 and before every probe and is
  independent of the agent — when it trips the run stops;
* Lookup #1 / #2 go through :func:`eunoia.search.search`, the same
  engine the Task 11 ``search_writeups`` MCP tool wraps (the tool
  itself is a closure bound to a server instance and is not
  importable; the harness calls the engine with the same parameters
  the tool would use: limit 5/3, modes pre_test/mid_test);
* Prove never performs a lookup — not even for a "stronger payload".
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.harness.budget import (
    LOOKUP1_LIMIT,
    LOOKUP2_LIMIT,
    MAX_NO_SIGNAL_PROBES,
    MAX_REQUERIES_PER_HYPOTHESIS,
    TOKENS_PER_RESULT,
    BudgetExceeded,
    TokenBudget,
)
from eunoia.harness.prove import Finding, prove_candidate
from eunoia.harness.state import Fingerprint, Hypothesis, RunState
from eunoia.models import WriteupVuln
from eunoia.safety.scope import Scope, ScopeGate
from eunoia.search import SearchResult, search

__all__ = [
    "KillSwitchStopped",
    "LookupCall",
    "Observation",
    "RunReport",
    "run_loop",
]

_MAX_PROBES_PER_HYPOTHESIS = MAX_NO_SIGNAL_PROBES * (
    1 + MAX_REQUERIES_PER_HYPOTHESIS
)
_MIN_FINGERPRINT_CONFIDENCE = 0.5


class KillSwitchStopped(Exception):
    """The operator kill switch tripped; the run stops immediately."""


@dataclass
class Observation:
    """One probe observation: status, body, timing, and what it means."""

    status: int
    body: str = ""
    timing_ms: float = 0.0
    signal: bool = False
    strange: bool = False
    new_service: str | None = None
    new_version: str | None = None
    redirect_url: str | None = None


@dataclass
class LookupCall:
    """One registry lookup inside a run (Lookup #1 or #2)."""

    query: str
    results: list = field(default_factory=list)
    limit: int = 5
    trigger: str = ""
    hypothesis_id: str | None = None
    cached: bool = False


@dataclass
class RunReport:
    """Final report of a run (step 9). Material findings need human
    review before they are final — the agent proposes severity, a
    human sets it."""

    status: str
    fingerprint: list = field(default_factory=list)
    hypotheses: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    lookup1_calls: list = field(default_factory=list)
    lookup2_calls: list = field(default_factory=list)
    retrieval_tokens: int = 0
    tokens_used: int = 0
    audit: list = field(default_factory=list)
    scratchpad: dict = field(default_factory=dict)
    human_review_required: bool = False
    coverage: dict = field(default_factory=dict)


def _default_fingerprint(target: str) -> list[Fingerprint]:
    """No live fingerprinting in MVP: returns no fingerprint.

    A lab run injects a ``fingerprinter`` (passive headers, favicon,
    error pages, asset paths) that returns ``Fingerprint`` values with
    ``confidence`` + ``bukti`` per technology. Without a minimal
    fingerprint the run stops before any lookup.
    """
    return []


def _check_kill_switch(kill_switch) -> None:
    if kill_switch is not None and kill_switch():
        raise KillSwitchStopped(
            "operator kill switch tripped; run stopped")


def _enforce_budget(state: RunState, budget: TokenBudget) -> None:
    """Prune at 50%, compact at 65% — never at 95% (§5.10)."""
    action = budget.action()
    if action == "compact":
        state.compact()
    elif action == "prune":
        state.prune()


def _lookup(state: RunState, budget: TokenBudget, query: dict,
            limit: int, trigger: str, session: Session | None,
            model, hypothesis_id: str | None = None,
            use_cache: bool = False) -> LookupCall | None:
    """One registry lookup with seen-id filtering and budget charging.

    Returns ``None`` when the retrieval budget is exhausted. For
    Lookup #2, ``use_cache`` serves a repeated normalized query from
    the run cache instead of sending it twice.
    """
    tech = tuple(sorted(t.lower() for t in (query.get("tech") or ())))
    key = "|".join([
        ",".join(tech),
        (query.get("vuln_class") or "").lower(),
        (query.get("evidence_pattern") or "").strip().lower(),
    ])
    if use_cache:
        cached = state.cached_lookup(key)
        if cached is not None:
            state.record_audit(
                "lookup2_cache_hit",
                {"query": key, "hypothesis_id": hypothesis_id})
            return LookupCall(query=key, results=list(cached), limit=limit,
                              trigger=trigger, hypothesis_id=hypothesis_id,
                              cached=True)
    try:
        results = search(query, limit=limit, session=session, model=model,
                         retrieval="hybrid")
    except Exception as exc:  # lookup failure is recorded, not fatal
        state.record_audit("lookup_failed",
                           {"query": key, "error": str(exc)})
        return LookupCall(query=key, results=[], limit=limit,
                          trigger=trigger, hypothesis_id=hypothesis_id)
    fresh = [r for r in results if not state.is_seen(r.writeup_id)]
    for result in fresh:
        state.mark_seen(result.writeup_id)
    try:
        budget.record_retrieval(TOKENS_PER_RESULT * len(fresh))
    except BudgetExceeded:
        state.budget_exhausted = True
        state.record_audit(
            "retrieval_budget_exhausted",
            {"cap": 20_000, "trigger": trigger})
        return None
    state.retrieval_tokens = budget.retrieval_used
    call = LookupCall(query=key, results=fresh, limit=limit,
                      trigger=trigger, hypothesis_id=hypothesis_id)
    if use_cache:
        state.cache_lookup(key, fresh)
    _enforce_budget(state, budget)
    return call


def run_loop(scope: Scope, lab_target: str, *, session: Session | None = None,
             model=None, probes_fail: int = 0, fingerprinter=None,
             probe_adapter=None, kill_switch=None) -> RunReport:
    """Execute steps 0–9 against a lab target the operator owns.

    ``fingerprinter`` maps a target to ``list[Fingerprint]`` (default:
    none — the run stops before any lookup). ``probe_adapter`` maps
    ``(hypothesis, target)`` to an :class:`Observation`; the default
    is a read-only stub that returns no signal for the first
    ``probes_fail`` probes and a signal afterwards. ``kill_switch``
    is a ``() -> bool`` callable checked at step 0 and before every
    probe. ``probes_fail`` is a test/lab knob, ignored when a custom
    ``probe_adapter`` is injected.

    With no ``session`` the run opens its own (like :func:`search`
    does) and closes it before returning.
    """
    own_session = session is None
    if own_session:
        session = Session(get_engine(get_settings()))
    assert session is not None
    try:
        return _execute(scope, lab_target, session=session, model=model,
                        probes_fail=probes_fail,
                        fingerprinter=fingerprinter,
                        probe_adapter=probe_adapter,
                        kill_switch=kill_switch)
    finally:
        if own_session:
            session.close()


def _vuln_class_by_writeup(session: Session,
                           results: list[SearchResult]) -> dict[str, str]:
    """First vuln row's class per writeup id (``SearchResult`` carries
    no class; Lookup #2 needs the real one for its query)."""
    if not results:
        return {}
    ids = [uuid.UUID(hex=r.writeup_id[2:]) for r in results]
    rows = (
        session.execute(
            select(WriteupVuln).where(WriteupVuln.writeup_id.in_(ids))
        )
        .scalars()
        .all()
    )
    by_id: dict[str, str] = {}
    for row in rows:
        api_id = f"w_{row.writeup_id.hex}"
        if api_id not in by_id and row.vuln_class:
            by_id[api_id] = row.vuln_class
    return by_id


def _execute(scope: Scope, lab_target: str, *, session: Session,
             model=None, probes_fail: int = 0, fingerprinter=None,
             probe_adapter=None, kill_switch=None) -> RunReport:
    state = RunState()
    budget = TokenBudget()
    probe_calls = {"n": 0}

    def _stub_probe(hypothesis: Hypothesis, target: str) -> Observation:
        probe_calls["n"] += 1
        if probe_calls["n"] <= probes_fail:
            return Observation(status=200, body="no new signal",
                               signal=False)
        return Observation(
            status=200,
            body=(f"anomalous response consistent with "
                  f"{hypothesis.technique}"),
            signal=True)

    probe = probe_adapter or _stub_probe
    lookup1_calls: list[LookupCall] = []
    lookup2_calls: list[LookupCall] = []
    findings: list[Finding] = []

    # --- step 0: Scope Gate (outside the planner) -----------------------
    ScopeGate.require(lab_target, scope)
    _check_kill_switch(kill_switch)
    state.record_audit("scope_gate_passed",
                       {"target": lab_target, "scope": scope.name or
                        list(scope.allowlist)})

    # --- step 1: Recon ----------------------------------------------------
    fingerprint = (fingerprinter or _default_fingerprint)(lab_target)
    state.fingerprint = list(fingerprint)
    main_techs = [f for f in state.fingerprint
                  if f.confidence >= _MIN_FINGERPRINT_CONFIDENCE]
    state.record_audit("recon_done",
                       {"technologies": [f.technology for f in main_techs]})
    if not main_techs:
        # No lookup before a minimal fingerprint exists (§5.8 step 1).
        return RunReport(
            status="stopped_no_fingerprint",
            fingerprint=state.fingerprint,
            audit=state.audit,
            scratchpad=state.scratchpad(),
            coverage={"technologies": [], "reason": "no minimal fingerprint"})

    # --- step 2: Lookup #1 — one query per main technology ---------------
    hypotheses: list[Hypothesis] = []
    for tech in main_techs:
        call = _lookup(
            state, budget,
            {"tech": (tech.technology,), "version": tech.version,
             "mode": "pre_test"},
            limit=LOOKUP1_LIMIT, trigger="lookup1",
            session=session, model=model)
        if call is None:  # retrieval budget exhausted
            break
        lookup1_calls.append(call)
        vuln_by_id = _vuln_class_by_writeup(session, call.results)
        for rank, result in enumerate(call.results):
            hyp = Hypothesis(
                id=f"h{len(hypotheses) + 1}",
                writeup_id=result.writeup_id,
                title=result.title,
                technique=vuln_by_id.get(result.writeup_id, "unknown"),
                target=lab_target,
                status="open",
                priority=rank,
            )
            state.add_hypothesis(hyp)
            hypotheses.append(hyp)
    state.record_audit(
        "lookup1_done",
        {"queries": len(lookup1_calls),
         "hypotheses": len(hypotheses)})

    # --- steps 3–7: plan, probe, Lookup #2, adapt -------------------------
    def _do_lookup2(hyp: Hypothesis, trigger: str,
                    evidence_pattern: str) -> LookupCall | None:
        if hyp.lookup2_count >= MAX_REQUERIES_PER_HYPOTHESIS:
            return None
        call = _lookup(
            state, budget,
            {"tech": tuple(f.technology for f in main_techs),
             "vuln_class": hyp.technique,
             "evidence_pattern": evidence_pattern or None,
             "mode": "mid_test"},
            limit=LOOKUP2_LIMIT, trigger=trigger,
            session=session, model=model,
            hypothesis_id=hyp.id, use_cache=True)
        if call is None:
            return None
        lookup2_calls.append(call)
        # Every invocation counts against the per-hypothesis cap of 2,
        # cached or not: a cache hit still consults the registry for
        # this hypothesis, it just does not re-send the query or
        # re-charge the token budget.
        hyp.lookup2_count += 1
        for result in call.results:
            hyp.evidence.append(f"lookup2:{result.writeup_id}")
        state.record_audit("lookup2_done",
                           {"hypothesis_id": hyp.id, "trigger": trigger,
                            "results": len(call.results),
                            "cached": call.cached})
        _enforce_budget(state, budget)
        return call

    for hyp in hypotheses:
        if state.budget_exhausted:
            break
        consecutive_no_signal = 0
        signalling: list[Observation] = []
        while hyp.probes_tried < _MAX_PROBES_PER_HYPOTHESIS:
            _check_kill_switch(kill_switch)
            ScopeGate.require(lab_target, scope)  # per execution call
            obs = probe(hyp, lab_target)
            hyp.probes_tried += 1
            state.record_observation(hyp.id, obs.body)
            if obs.redirect_url and not ScopeGate.check_redirect(
                    lab_target, obs.redirect_url, scope):
                state.record_audit(
                    "redirect_blocked",
                    {"hypothesis_id": hyp.id,
                     "redirect_url": obs.redirect_url})
                obs = Observation(status=obs.status, body=obs.body,
                                  signal=False)
            if obs.signal:
                hyp.status = "testing"
                signalling.append(obs)
                # Trigger (d): candidate needs a safe verification path.
                _do_lookup2(hyp, "candidate_verification",
                            obs.body[:200])
                break
            if obs.strange or obs.new_service or obs.new_version:
                # Triggers (b)/(c): strange response, new service/version.
                pattern = (obs.new_service or obs.new_version
                           or obs.body[:200])
                _do_lookup2(hyp, "strange_response_or_new_service",
                            pattern)
                consecutive_no_signal = 0
                continue
            consecutive_no_signal += 1
            if consecutive_no_signal >= MAX_NO_SIGNAL_PROBES:
                # Trigger (a): 3 consecutive probes with no new signal.
                if hyp.lookup2_count >= MAX_REQUERIES_PER_HYPOTHESIS:
                    hyp.status = "debunked"
                    state.record_audit(
                        "hypothesis_debunked",
                        {"hypothesis_id": hyp.id,
                         "reason": "no signal after max re-queries"})
                    break
                _do_lookup2(hyp, "no_signal", "")
                consecutive_no_signal = 0
                # Adapt: revise (keep the hypothesis, priority unchanged)
                # and probe again; a debunked hypothesis is never
                # re-queried — it is recorded and the loop moves on.
        if hyp.status == "testing" and signalling:
            # --- step 8: Prove (no lookup here) ---------------------------
            steps = [f"Replay the safe read probe for {hyp.technique} "
                     f"against {hyp.target} (lab-only)"]
            finding = prove_candidate(hyp, signalling, steps)
            findings.append(finding)
            if finding.status == "confirmed":
                hyp.status = "confirmed"
            state.record_audit("prove_done",
                               {"hypothesis_id": hyp.id,
                                "status": finding.status})
        elif hyp.status == "open":
            # Probes exhausted without a signal and without hitting the
            # debunk branch (e.g. budget stopped the run): leave open,
            # report it as untested rather than as a finding.
            state.record_audit("hypothesis_untested",
                               {"hypothesis_id": hyp.id})

    # --- step 9: Report + STOP --------------------------------------------
    confirmed = [f for f in findings if f.status == "confirmed"]
    coverage = {
        "technologies": [f.technology for f in main_techs],
        "hypotheses_total": len(hypotheses),
        "hypotheses_confirmed": sum(
            1 for h in hypotheses if h.status == "confirmed"),
        "hypotheses_debunked": sum(
            1 for h in hypotheses if h.status == "debunked"),
        "hypotheses_untested": sum(
            1 for h in hypotheses if h.status == "open"),
        "findings_confirmed": len(confirmed),
        "findings_unverified": sum(
            1 for f in findings if f.status == "unverified"),
        "retrieval_tokens": budget.retrieval_used,
        "budget_exhausted": state.budget_exhausted,
    }
    state.record_audit("report_done", {"findings": len(findings)})
    return RunReport(
        status=("completed_budget_exhausted" if state.budget_exhausted
                else "completed"),
        fingerprint=state.fingerprint,
        hypotheses=hypotheses,
        findings=findings,
        lookup1_calls=lookup1_calls,
        lookup2_calls=lookup2_calls,
        retrieval_tokens=budget.retrieval_used,
        tokens_used=budget.used,
        audit=state.audit,
        scratchpad=state.scratchpad(),
        human_review_required=bool(confirmed),
        coverage=coverage)
