"""Approval tiers + LLM-as-judge (spec §6.3).

Tiers (binding):

- autonomous — passive recon, registry queries, read-only probes within
  rate limits; needs only the Scope Gate.
- needs_approval — exploit, credential use, data access, state change,
  lateral movement, anything that could disrupt a service; needs an
  LLM-as-judge pass AND a recorded human approval before execution.
- unapprovable — destructive, exfiltration, out-of-scope,
  non-consenting target; cannot be approved, blocked in code.

§9 Q4 debt (recorded, not decided): who runs the LLM-as-judge — the
same model with a different prompt, or a separate model — is still
undecided, and so are its cost and independence. Until that is decided
and measured, v1 relies on the deterministic Scope Gate as the primary
gate and treats the judge as a separately-configured component. A judge
configured with the planner's own model is refused unless the caller
explicitly acknowledges it in writing
(``JudgeConfig(acknowledge_same_model=True)``): the planner must never
judge itself silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Callable, Protocol

JUDGE_Q4_DEBT = (
    "§9 Q4 (open): who runs the LLM-as-judge is undecided — same model "
    "with a different prompt, or a separate model. Cost and independence "
    "are undecided. Until decided and measured, the deterministic Scope "
    "Gate is the primary gate; the judge is a separately-configured "
    "component, and a same-model judge requires an explicit written "
    "acknowledgement (JudgeConfig.acknowledge_same_model)."
)

JUDGE_PROMPT = (
    "You are a safety judge, not the planner. Decide only whether the "
    "proposed action is allowed under the engagement scope and the "
    "approval tiers. Reply with exactly one line: APPROVE or DENY, "
    "followed by a short reason. When in doubt, DENY."
)


class ActionKind(str, Enum):
    # Autonomous tier.
    PASSIVE_RECON = "passive_recon"
    REGISTRY_QUERY = "registry_query"
    READ_PROBE = "read_probe"
    # Needs-approval tier.
    EXPLOIT = "exploit"
    CREDENTIAL_USE = "credential_use"
    DATA_ACCESS = "data_access"
    STATE_CHANGE = "state_change"
    LATERAL_MOVEMENT = "lateral_movement"
    DISRUPTIVE = "disruptive"
    # Unapprovable tier.
    DESTRUCTIVE = "destructive"
    EXFILTRATION = "exfiltration"
    OUT_OF_SCOPE = "out_of_scope"
    NON_CONSENSUAL = "non_consensual"

    @property
    def tier(self) -> str:
        if self in (ActionKind.PASSIVE_RECON, ActionKind.REGISTRY_QUERY,
                    ActionKind.READ_PROBE):
            return "autonomous"
        if self in (ActionKind.DESTRUCTIVE, ActionKind.EXFILTRATION,
                    ActionKind.OUT_OF_SCOPE, ActionKind.NON_CONSENSUAL):
            return "unapprovable"
        return "needs_approval"


@dataclass(frozen=True)
class Action:
    """One proposed agent action, already scope-checked by the caller."""

    kind: ActionKind
    target: str
    description: str = ""
    in_scope: bool = True


@dataclass(frozen=True)
class HumanApproval:
    """A recorded human approval: who, when, and why."""

    approver: str
    at: datetime
    note: str = ""


@dataclass(frozen=True)
class JudgeVerdict:
    passed: bool
    reason: str
    model: str
    prompt_version: str


@dataclass(frozen=True)
class JudgeConfig:
    """Separate configuration for the judge (never the planner's config).

    ``planner_model`` is the model running the planner; when it equals
    ``model`` the judge would be the planner judging itself, which is
    refused unless ``acknowledge_same_model`` is set — the written note
    §6.3 requires.
    """

    model: str
    prompt_version: str
    planner_model: str | None = None
    acknowledge_same_model: bool = False

    def __post_init__(self) -> None:
        if (self.planner_model is not None
                and self.model == self.planner_model
                and not self.acknowledge_same_model):
            raise ValueError(
                "judge model must differ from the planner model, or the "
                "caller must acknowledge the same-model judge in writing "
                "(JudgeConfig.acknowledge_same_model=True). "
                "See §9 Q4 debt: " + JUDGE_Q4_DEBT)


class Judge(Protocol):
    def review(self, action: Action, config: JudgeConfig) -> JudgeVerdict:
        ...


@dataclass
class StubJudge:
    """Deterministic stand-in judge for tests and for runs with no LLM
    wired: returns a fixed verdict. Never used as a production judge
    without a recorded decision — a stub that always passes is not a
    gate, it is a test double."""

    passed: bool
    reason: str = ""

    def review(self, action: Action, config: JudgeConfig) -> JudgeVerdict:
        return JudgeVerdict(passed=self.passed,
                            reason=self.reason or "stub verdict",
                            model=config.model,
                            prompt_version=config.prompt_version)


class LLMJudge:
    """Judge backed by an injected model function.

    ``model_fn`` receives the judge prompt plus the action and must
    return a reply starting with APPROVE or DENY. Anything else fails
    closed (DENY). The model function is injected: this class never
    picks a model itself, so the judge's model stays a separate,
    explicit configuration from the planner's.
    """

    def __init__(self, model_fn: Callable[[str], str]) -> None:
        self._model_fn = model_fn

    def review(self, action: Action, config: JudgeConfig) -> JudgeVerdict:
        prompt = (
            f"{JUDGE_PROMPT}\n\nAction: {action.kind.value}\n"
            f"Target: {action.target}\n"
            f"Description: {action.description}\n"
            f"In scope: {action.in_scope}"
        )
        reply = (self._model_fn(prompt) or "").strip()
        # Final review triage, Task 13: split on ANY whitespace, so
        # "APPROVE\n<reason>" is a legitimate APPROVE — partition(" ")
        # failed closed on a newline-separated verdict.
        parts = reply.split(None, 1)
        head = parts[0] if parts else ""
        reason = parts[1] if len(parts) > 1 else ""
        passed = head.upper() == "APPROVE"
        return JudgeVerdict(
            passed=passed,
            reason=(reason.strip() or head or "no verdict returned"),
            model=config.model,
            prompt_version=config.prompt_version)


@dataclass(frozen=True)
class ApprovalDecision:
    allowed: bool
    tier: str
    reason: str
    judge_passed: bool | None = None
    human_approved: bool = False
    judge_model: str | None = None


class ApprovalGate:
    """Deterministic tier enforcement. No model involved in the decision
    itself — the judge verdict and the human approval are inputs."""

    @staticmethod
    def decide(action: Action, *, scope_ok: bool,
               judge_verdict: JudgeVerdict | None = None,
               human_approval: HumanApproval | None = None) -> ApprovalDecision:
        tier = action.kind.tier
        if not scope_ok or not action.in_scope:
            return ApprovalDecision(
                allowed=False, tier=tier,
                reason="out of scope: Scope Gate did not pass")
        if tier == "unapprovable":
            return ApprovalDecision(
                allowed=False, tier=tier,
                reason=f"{action.kind.value} can never be approved")
        if tier == "autonomous":
            return ApprovalDecision(
                allowed=True, tier=tier,
                reason="autonomous tier; Scope Gate passed")
        # needs_approval: judge pass AND recorded human approval.
        judge_passed = judge_verdict.passed if judge_verdict else None
        if judge_verdict is None or not judge_verdict.passed:
            return ApprovalDecision(
                allowed=False, tier=tier,
                reason="LLM-as-judge did not pass",
                judge_passed=judge_passed,
                human_approved=human_approval is not None,
                judge_model=judge_verdict.model if judge_verdict else None)
        if human_approval is None:
            return ApprovalDecision(
                allowed=False, tier=tier,
                reason="no recorded human approval",
                judge_passed=True, human_approved=False,
                judge_model=judge_verdict.model)
        return ApprovalDecision(
            allowed=True, tier=tier,
            reason="judge passed and human approval recorded",
            judge_passed=True, human_approved=True,
            judge_model=judge_verdict.model)
