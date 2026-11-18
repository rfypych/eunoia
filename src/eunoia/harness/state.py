"""Run state for the reference harness (spec §5.8, §5.10).

Run state lives OUTSIDE the context window: hypotheses (with status
``open``/``testing``/``confirmed``/``debunked``), evidence, tried
steps, seen-ids, the run lookup cache, and the audit trail. Only a
structured scratchpad is injected per step — never full text.

Seen-ids: the harness refuses to return or re-read a writeup id
already returned in the run. The run lookup cache serves a repeated
normalized query from cache instead of sending it twice.
"""

from __future__ import annotations

from dataclasses import dataclass, field

_OBSERVATION_STORE_MAX = 2000   # chars kept per observation pre-compaction
_OBSERVATION_SUMMARY_MAX = 120  # chars kept per observation post-compaction


@dataclass(frozen=True)
class Fingerprint:
    """One fingerprinted technology: product, version, confidence, bukti.

    Fingerprinting is evidence, not proof — a low-confidence version
    is kept as a candidate (score lowered downstream), never dropped.
    """

    technology: str
    version: str | None = None
    confidence: float = 0.0
    bukti: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "bukti", tuple(self.bukti))


@dataclass
class Hypothesis:
    """One attack hypothesis from a Lookup #1 writeup."""

    id: str
    writeup_id: str
    title: str
    technique: str
    target: str
    status: str = "open"  # open | testing | confirmed | debunked
    priority: int = 0
    evidence: list[str] = field(default_factory=list)
    probes_tried: int = 0
    lookup2_count: int = 0
    verification_steps: list[str] = field(default_factory=list)


@dataclass
class RunState:
    """Mutable state for one harness run; never serialized into a prompt."""

    hypotheses: dict[str, Hypothesis] = field(default_factory=dict)
    seen_ids: set[str] = field(default_factory=set)
    lookup_cache: dict[str, list] = field(default_factory=dict)
    observations: dict[str, list[str]] = field(default_factory=dict)
    audit: list[dict] = field(default_factory=list)
    fingerprint: list[Fingerprint] = field(default_factory=list)
    retrieval_tokens: int = 0
    compacted: bool = False
    budget_exhausted: bool = False
    lookup_failures: int = 0
    handoff_summary: str = ""

    # --- hypotheses ----------------------------------------------------

    def add_hypothesis(self, hypothesis: Hypothesis) -> None:
        self.hypotheses.setdefault(hypothesis.id, hypothesis)

    # --- seen-ids ------------------------------------------------------

    def mark_seen(self, writeup_id: str) -> None:
        self.seen_ids.add(writeup_id)

    def is_seen(self, writeup_id: str) -> bool:
        return writeup_id in self.seen_ids

    def unseen(self, writeup_ids: list[str]) -> list[str]:
        """Filter an id list down to ids not yet returned in this run."""
        return [wid for wid in writeup_ids if wid not in self.seen_ids]

    # --- run lookup cache ----------------------------------------------

    def cached_lookup(self, normalized_query: str) -> list | None:
        return self.lookup_cache.get(normalized_query)

    def cache_lookup(self, normalized_query: str, results: list) -> None:
        self.lookup_cache[normalized_query] = list(results)

    # --- observations / audit ------------------------------------------

    def record_observation(self, hypothesis_id: str, body: str) -> None:
        """Store one probe observation, bounded; full text never enters
        the scratchpad — only a summary of it does."""
        stored = (body or "")[:_OBSERVATION_STORE_MAX]
        self.observations.setdefault(hypothesis_id, []).append(stored)

    def record_audit(self, event: str, detail: dict | None = None) -> None:
        self.audit.append({"event": event, "detail": detail or {}})

    # --- scratchpad / compaction ----------------------------------------

    def scratchpad(self) -> dict:
        """Structured summary injected per step: no excerpts, no bodies,
        no full text — counts and statuses only."""
        return {
            "fingerprint": [
                {"technology": f.technology, "version": f.version,
                 "confidence": f.confidence}
                for f in self.fingerprint
            ],
            "hypotheses": [
                {"id": h.id, "technique": h.technique,
                 "status": h.status, "priority": h.priority,
                 "probes_tried": h.probes_tried}
                for h in sorted(self.hypotheses.values(),
                                key=lambda h: h.priority)
            ],
            "seen_ids_count": len(self.seen_ids),
            "retrieval_tokens": self.retrieval_tokens,
            "audit_events": len(self.audit),
            "compacted": self.compacted,
        }

    def prune(self) -> None:
        """Prune line (50%): drop the oldest half of stored tool output."""
        for hyp_id, obs in self.observations.items():
            keep = obs[len(obs) // 2:] if len(obs) > 1 else obs
            self.observations[hyp_id] = keep
        self.record_audit("context_pruned",
                          {"reason": "usage reached the 50% prune line"})

    def compact(self) -> None:
        """Compaction line (65%): drop summarized tool output, keep a
        one-line summary per observation; the handoff summary +
        system prompt + last 2 turns start the next segment.

        Final review triage, Task 14: the handoff summary is actually
        constructed here now (it used to be only claimed in the audit
        string) and stored on ``self.handoff_summary``.
        """
        for hyp_id, obs in self.observations.items():
            self.observations[hyp_id] = [
                o[:_OBSERVATION_SUMMARY_MAX] for o in obs
            ]
        self.compacted = True
        techs = ", ".join(
            f.technology for f in self.fingerprint) or "no fingerprint"
        by_status: dict[str, int] = {}
        for hyp in self.hypotheses.values():
            by_status[hyp.status] = by_status.get(hyp.status, 0) + 1
        status_part = ", ".join(
            f"{n} {s}" for s, n in sorted(by_status.items())
        ) or "no hypotheses"
        self.handoff_summary = (
            f"Compacted at 65%: {techs}; hypotheses {status_part}; "
            f"{len(self.seen_ids)} writeups seen; "
            f"{len(self.audit)} audit events."
        )
        self.record_audit(
            "context_compacted",
            {"reason": "usage reached the 65% summarize line",
             "handoff_summary": self.handoff_summary})
