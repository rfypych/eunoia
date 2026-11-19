"""Evidence ranking (spec §5.9).

Pure functions: no DB, no network, no model. The weights below are the
spec's verbatim proposal — they must be validated against the golden set
(Task 15) before being treated as measured defaults, and re-measured
whenever the embedding model or ranking changes.

Pre-test (Lookup #1)::

    score = stack_match * 0.40 + exploited * 0.25 + severity * 0.15
          + recency * 0.10 + verified * 0.10

Mid-test (Lookup #2)::

    score = stack_match * 0.30 + technique_similarity * 0.20
          + exploited * 0.25 + severity * 0.15 + recency * 0.05
          + verified * 0.05

Every component is normalized to 0–1; unknown fields are 0, never
invented (spec hard rule 2). ``rank_pre_test`` drops results with
``stack_match == 0`` (spec hard rule 5); ``rank_mid_test`` keeps them.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "ScoreComponents",
    "breakdown_mid_test",
    "breakdown_pre_test",
    "normalize_exploited",
    "normalize_recency",
    "normalize_severity",
    "normalize_verified",
    "rank_mid_test",
    "rank_pre_test",
    "score_mid_test",
    "score_pre_test",
]

PRE_TEST_WEIGHTS = {
    "stack_match": 0.40,
    "exploited": 0.25,
    "severity": 0.15,
    "recency": 0.10,
    "verified": 0.10,
}

MID_TEST_WEIGHTS = {
    "stack_match": 0.30,
    "technique_similarity": 0.20,
    "exploited": 0.25,
    "severity": 0.15,
    "recency": 0.05,
    "verified": 0.05,
}

_SEVERITY_ENUM = {"critical": 1.0, "high": 0.75, "medium": 0.5, "low": 0.25}


@dataclass(frozen=True)
class ScoreComponents:
    """One result's normalized 0–1 components (§5.9 table)."""

    stack_match: float
    exploited: float
    severity: float
    recency: float
    verified: float
    technique_similarity: float = 0.0


def normalize_exploited(kev: bool, epss: float | None) -> float:
    """KEV = 1.0; EPSS ≥ 0.10 = 0.7; 0.04–0.10 = 0.4; < 0.04 = 0.2;
    no data = 0 (not "safe", just unknown)."""
    if kev:
        return 1.0
    if epss is None:
        return 0.0
    if epss >= 0.10:
        return 0.7
    if epss >= 0.04:
        return 0.4
    return 0.2


def normalize_severity(
    cvss_score: float | None, severity: str | None
) -> tuple[float, bool]:
    """CVSS/10, else the severity enum; (0.0, True) when neither exists —
    the caller must flag the missing severity, never guess it."""
    if cvss_score is not None:
        return round(min(max(float(cvss_score), 0.0), 10.0) / 10.0, 4), False
    if severity:
        value = _SEVERITY_ENUM.get(severity.lower())
        if value is not None:
            return value, False
    return 0.0, True


def normalize_recency(age_days: float | None) -> float:
    """``1 / (1 + age_days / 180)``; unknown date = 0 (oldest), never
    treated as fresh."""
    if age_days is None:
        return 0.0
    return round(1.0 / (1.0 + max(age_days, 0.0) / 180.0), 4)


def normalize_verified(
    bounty_verified: bool,
    bounty_amount: float | None,
    severity_source: str | None,
    has_severity: bool = False,
) -> tuple[float, str]:
    """Platform-verified = 1.0 (bounty verified, or severity straight
    from a platform API); author-claimed = 0.5; nothing claimed = 0."""
    if bounty_verified or (severity_source or "").lower() == "hackerone":
        return 1.0, "platform-verified"
    if bounty_amount is not None or has_severity:
        return 0.5, "author-claimed, unverified"
    return 0.0, "unverified"


def score_pre_test(components: ScoreComponents) -> float:
    """Weighted pre-test score (§5.9)."""
    return round(
        components.stack_match * PRE_TEST_WEIGHTS["stack_match"]
        + components.exploited * PRE_TEST_WEIGHTS["exploited"]
        + components.severity * PRE_TEST_WEIGHTS["severity"]
        + components.recency * PRE_TEST_WEIGHTS["recency"]
        + components.verified * PRE_TEST_WEIGHTS["verified"],
        4,
    )


def score_mid_test(components: ScoreComponents) -> float:
    """Weighted mid-test score (§5.9)."""
    return round(
        components.stack_match * MID_TEST_WEIGHTS["stack_match"]
        + components.technique_similarity
        * MID_TEST_WEIGHTS["technique_similarity"]
        + components.exploited * MID_TEST_WEIGHTS["exploited"]
        + components.severity * MID_TEST_WEIGHTS["severity"]
        + components.recency * MID_TEST_WEIGHTS["recency"]
        + components.verified * MID_TEST_WEIGHTS["verified"],
        4,
    )


def breakdown_pre_test(components: ScoreComponents) -> dict:
    """The five pre-test components, rounded for display."""
    return {
        "stack_match": round(components.stack_match, 4),
        "exploited": round(components.exploited, 4),
        "severity": round(components.severity, 4),
        "recency": round(components.recency, 4),
        "verified": round(components.verified, 4),
    }


def breakdown_mid_test(components: ScoreComponents) -> dict:
    """All six mid-test components, rounded for display."""
    breakdown = breakdown_pre_test(components)
    breakdown["technique_similarity"] = round(
        components.technique_similarity, 4
    )
    return breakdown


def rank_pre_test(results: list) -> list:
    """Sort by score desc; drop ``stack_match == 0`` (spec hard rule 5:
    a result unrelated to the target stack never enters pre-test)."""
    ranked = [r for r in results if r.score_breakdown.get("stack_match", 0) != 0]
    return sorted(ranked, key=lambda r: r.score, reverse=True)


def rank_mid_test(results: list) -> list:
    """Sort by score desc; ``stack_match == 0`` is allowed in mid-test
    semantic search when the technique is very similar."""
    return sorted(results, key=lambda r: r.score, reverse=True)
