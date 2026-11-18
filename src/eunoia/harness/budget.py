"""Token budget (spec §5.10).

All numbers are the spec's design targets for a 200K-token window,
not measurements — they must be re-measured per model. The harness
enforces them in code, not just in docs:

* retrieval across the whole run: max 20,000 tokens (hard cap);
* Lookup #1: limit 5 per technology; Lookup #2: limit 3;
* reserve line 20% (40,000) — never touched;
* prune line 50% (100,000) — drop summarized tool output;
* summarize/compaction line 65% (130,000) — handoff summary + system
  prompt + last 2 turns, then a fresh segment. Never at 95%.

Token estimates use ``len(text) // 4`` (the same rough estimate Task
12 uses for the <5000-token skill bound); they are a budget guard,
not a tokenizer.
"""

from __future__ import annotations

from dataclasses import dataclass

WINDOW_TOKENS = 200_000
RESERVE_TOKENS = 40_000          # 20% — never touched
PRUNE_LINE = 100_000             # 50% — drop summarized tool output
COMPACT_LINE = 130_000           # 65% — handoff summary, fresh segment
RETRIEVAL_CAP = 20_000           # max retrieval tokens per run
LOOKUP1_LIMIT = 5
LOOKUP2_LIMIT = 3
MAX_REQUERIES_PER_HYPOTHESIS = 2
MAX_NO_SIGNAL_PROBES = 3

# One ranked result costs ~150–250 tokens in context (spec §5.10).
TOKENS_PER_RESULT = 200


class BudgetExceeded(Exception):
    """A lookup would push retrieval past the 20,000-token run cap."""


def estimate_tokens(text: str | None) -> int:
    """Rough token estimate: 1 token per 4 characters, minimum 1."""
    if not text:
        return 1
    return max(1, len(text) // 4)


@dataclass
class TokenBudget:
    """Running token ledger for one harness run."""

    used: int = 0
    retrieval_used: int = 0

    def record_retrieval(self, tokens: int) -> None:
        """Charge retrieval tokens; raises when the run cap breaks."""
        if self.retrieval_used + tokens > RETRIEVAL_CAP:
            raise BudgetExceeded(
                f"retrieval budget exceeded: {self.retrieval_used} + "
                f"{tokens} > {RETRIEVAL_CAP} tokens/run")
        self.retrieval_used += tokens
        self.used += tokens

    def record_state(self, tokens: int) -> None:
        """Charge non-retrieval context (state, history, scratchpad)."""
        self.used += tokens

    @property
    def usage_ratio(self) -> float:
        return self.used / WINDOW_TOKENS

    def action(self) -> str:
        """``"ok"`` | ``"prune"`` | ``"compact"`` for the current usage.

        The reserve (top 20%) is never spent, so the lines are checked
        against the full window: prune at 50%, compact at 65%.
        """
        if self.used >= COMPACT_LINE:
            return "compact"
        if self.used >= PRUNE_LINE:
            return "prune"
        return "ok"
