"""Safety gate (spec §6): Scope Gate, approval tiers, audit, takedown.

The safety layer lives outside the planner: the planner is the thing
being constrained, so it must never be the sole judge of its own
authority. All enforcement here is deterministic code, not prompt text.
"""

from __future__ import annotations

from eunoia.safety.approvals import (
    Action,
    ActionKind,
    ApprovalDecision,
    ApprovalGate,
    HumanApproval,
    Judge,
    JudgeConfig,
    JudgeVerdict,
    LLMJudge,
    StubJudge,
)
from eunoia.safety.audit import APPEND_ONLY_TRIGGER_SQL, audit_append
from eunoia.safety.quality import QualityGateResult, detect_language, quality_gate
from eunoia.safety.scope import Scope, ScopeBlocked, ScopeGate
from eunoia.safety.secrets_scan import Finding, contains_secret, scan_secrets
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

__all__ = [
    "APPEND_ONLY_TRIGGER_SQL",
    "DMCA_AGENT_EMAIL",
    "DMCA_AGENT_NAME",
    "TAKEDOWN_STUB",
    "Action",
    "ActionKind",
    "ApprovalDecision",
    "ApprovalGate",
    "Finding",
    "HumanApproval",
    "Judge",
    "JudgeConfig",
    "JudgeVerdict",
    "LLMJudge",
    "QualityGateResult",
    "Scope",
    "ScopeBlocked",
    "ScopeGate",
    "StubJudge",
    "acknowledge_by",
    "apply_author_removal",
    "apply_takedown",
    "audit_append",
    "contains_secret",
    "detect_language",
    "quality_gate",
    "scan_secrets",
    "stub_by",
    "validate_notice",
]
