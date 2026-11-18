"""Task 9: ranking formula (§5.9) — pure-function tests, no DB.

Weights are the spec's verbatim proposal (pre-test stack 0.40 /
exploited 0.25 / severity 0.15 / recency 0.10 / verified 0.10; mid-test
stack 0.30 / technique 0.20 / exploited 0.25 / severity 0.15 /
recency 0.05 / verified 0.05). The weights themselves are a PRD
proposal to be validated against the golden set (Task 15) — these tests
pin the implementation to the spec as written.
"""

from __future__ import annotations

from eunoia.ranking import (
    ScoreComponents,
    normalize_exploited,
    normalize_recency,
    normalize_severity,
    normalize_verified,
    rank_mid_test,
    rank_pre_test,
    score_mid_test,
    score_pre_test,
)
from eunoia.search import SearchResult


def _result(writeup_id: str, stack_match: float, score: float) -> SearchResult:
    return SearchResult(
        writeup_id=writeup_id,
        title=f"writeup {writeup_id}",
        score=score,
        score_breakdown={"stack_match": stack_match},
        match_reason="test",
        verified=True,
        verified_label="platform-verified",
        fetched_at=None,
        indexed_at=None,
        freshness={"age_days": None, "label": "unknown"},
    )


# --- component normalizers -------------------------------------------------


def test_exploited_kev_is_one():
    assert normalize_exploited(kev=True, epss=None) == 1.0
    assert normalize_exploited(kev=True, epss=0.99) == 1.0


def test_exploited_epss_bands():
    assert normalize_exploited(kev=False, epss=0.50) == 0.7
    assert normalize_exploited(kev=False, epss=0.10) == 0.7
    assert normalize_exploited(kev=False, epss=0.05) == 0.4
    assert normalize_exploited(kev=False, epss=0.04) == 0.4
    assert normalize_exploited(kev=False, epss=0.01) == 0.2


def test_exploited_no_data_is_zero():
    assert normalize_exploited(kev=False, epss=None) == 0.0


def test_severity_cvss_over_ten():
    score, missing = normalize_severity(cvss_score=9.8, severity=None)
    assert score == 0.98
    assert missing is False


def test_severity_enum_fallback():
    assert normalize_severity(None, "critical") == (1.0, False)
    assert normalize_severity(None, "high") == (0.75, False)
    assert normalize_severity(None, "medium") == (0.5, False)
    assert normalize_severity(None, "low") == (0.25, False)


def test_severity_none_is_zero_and_flagged():
    assert normalize_severity(None, None) == (0.0, True)


def test_recency_decay():
    assert normalize_recency(0) == 1.0
    assert normalize_recency(180) == 0.5
    assert normalize_recency(1800) == 0.0909  # 1 / (1 + 1800/180) = 1/11


def test_recency_unknown_date_is_zero():
    assert normalize_recency(None) == 0.0


def test_verified_platform_is_one():
    score, label = normalize_verified(
        bounty_verified=True, bounty_amount=None, severity_source="hackerone"
    )
    assert score == 1.0
    assert label == "platform-verified"


def test_verified_author_claim_is_half():
    score, label = normalize_verified(
        bounty_verified=False, bounty_amount=500, severity_source=None
    )
    assert score == 0.5
    assert label == "author-claimed, unverified"


def test_verified_none_is_zero():
    score, label = normalize_verified(
        bounty_verified=False, bounty_amount=None, severity_source=None
    )
    assert score == 0.0
    assert label == "unverified"


# --- weighted scores -------------------------------------------------------


def test_pre_test_weights_sum_to_one():
    all_one = ScoreComponents(1.0, 1.0, 1.0, 1.0, 1.0)
    assert score_pre_test(all_one) == 1.0
    stack_only = ScoreComponents(1.0, 0.0, 0.0, 0.0, 0.0)
    assert score_pre_test(stack_only) == 0.40
    exploited_only = ScoreComponents(0.0, 1.0, 0.0, 0.0, 0.0)
    assert score_pre_test(exploited_only) == 0.25


def test_mid_test_weights_sum_to_one():
    all_one = ScoreComponents(1.0, 1.0, 1.0, 1.0, 1.0, 1.0)
    assert score_mid_test(all_one) == 1.0
    stack_only = ScoreComponents(1.0, 0.0, 0.0, 0.0, 0.0, 0.0)
    assert score_mid_test(stack_only) == 0.30
    technique_only = ScoreComponents(0.0, 0.0, 0.0, 0.0, 0.0, 1.0)
    assert score_mid_test(technique_only) == 0.20


# --- rank functions --------------------------------------------------------


def test_rank_pre_test_excludes_stack_zero():
    results = [
        _result("w_a", stack_match=0.0, score=0.95),
        _result("w_b", stack_match=1.0, score=0.50),
    ]
    ranked = rank_pre_test(results)
    assert [r.writeup_id for r in ranked] == ["w_b"]


def test_rank_mid_test_keeps_stack_zero():
    results = [
        _result("w_a", stack_match=0.0, score=0.95),
        _result("w_b", stack_match=1.0, score=0.50),
    ]
    ranked = rank_mid_test(results)
    assert [r.writeup_id for r in ranked] == ["w_a", "w_b"]


def test_rank_orders_by_score_desc():
    results = [
        _result("w_a", stack_match=1.0, score=0.30),
        _result("w_b", stack_match=1.0, score=0.90),
        _result("w_c", stack_match=1.0, score=0.60),
    ]
    assert [r.writeup_id for r in rank_pre_test(results)] == ["w_b", "w_c", "w_a"]
