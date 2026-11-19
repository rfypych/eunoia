"""Prove step (spec §5.8 step 8): candidate → confirmed / unverified /
debunked, with minimal reproduction steps and evidence.

Rules (binding):

* a candidate is ``confirmed`` only with a signalling observation AND
  minimal reproduction steps; otherwise it is ``unverified``, never a
  finding;
* a hypothesis already marked ``debunked`` stays ``debunked``;
* evidence never carries sensitive data — it is passed through the
  Task 13 secret scan and every match is redacted;
* NO new lookup happens here for a "stronger payload": Prove takes
  observations and steps only, never a search function.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from eunoia.harness.state import Hypothesis
from eunoia.safety.secrets_scan import scan_secrets

REDACTED = "[REDACTED {pattern}]"


def sanitize_evidence(text: str | None) -> str:
    """Replace every secret-pattern match with a redaction marker.

    The secret itself never survives into the finding — only the
    pattern name is kept, so the evidence stays auditable without
    leaking the credential.
    """
    if not text:
        return ""
    findings = scan_secrets(text)
    if not findings:
        return text
    out: list[str] = []
    cursor = 0
    for finding in findings:
        out.append(text[cursor:finding.start])
        out.append(REDACTED.format(pattern=finding.pattern))
        cursor = finding.end
    out.append(text[cursor:])
    return "".join(out)


@dataclass
class Finding:
    """One proved (or unproved) candidate."""

    hypothesis_id: str
    status: str  # confirmed | unverified | debunked
    reproduction_steps: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    reason: str = ""


def prove_candidate(hypothesis: Hypothesis, observations: list,
                    reproduction_steps: list[str]) -> Finding:
    """Verdict one candidate from its probe observations.

    ``observations`` are the harness ``Observation`` objects (duck-typed
    on ``.signal`` and ``.body``). No lookup is performed here.
    """
    if hypothesis.status == "debunked":
        return Finding(
            hypothesis_id=hypothesis.id, status="debunked",
            reproduction_steps=list(reproduction_steps),
            reason="hypothesis was debunked during Adapt; not re-proved")

    signalling = [o for o in observations if getattr(o, "signal", False)]
    evidence = [
        sanitize_evidence(getattr(o, "body", "") or "")
        for o in signalling
    ]
    evidence = [e for e in evidence if e]

    if not signalling:
        return Finding(
            hypothesis_id=hypothesis.id, status="unverified",
            reproduction_steps=list(reproduction_steps),
            reason="no signalling observation; cannot be reproduced")
    if not reproduction_steps:
        return Finding(
            hypothesis_id=hypothesis.id, status="unverified",
            reproduction_steps=[],
            evidence=evidence,
            reason="signal observed but no minimal reproduction steps")
    return Finding(
        hypothesis_id=hypothesis.id, status="confirmed",
        reproduction_steps=list(reproduction_steps),
        evidence=evidence,
        reason="signal reproduced with minimal steps")
