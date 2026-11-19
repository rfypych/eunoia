"""T10: three showcases with evidence.

Each showcase must have target, question, steps, evidence, numbers and
limitations. The evidence rows (report id, rank, score) were measured
live against production on 19 Nov 2026 and are pinned here so they
cannot drift silently: if the corpus is re-measured, update the doc
and this test together. The aggregate numbers must match
``docs/reports/corpus-500.md`` (same convention as the T7 acceptance
test: pinned by consistency, not re-derived in CI, because CI does
not have the 500-row real corpus).

No software-creation methodology wording in the doc.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DOC = REPO / "docs" / "showcases.md"
REPORT = REPO / "docs" / "reports" / "corpus-500.md"

# (report id, rank, score) measured live 19 Nov 2026, anonymous
# keyword search, limit 5. Query and lookup are in the comment.
PINNED_EVIDENCE = [
    # Showcase 1: q=CSRF, lookup=pre_test (default)
    ("3882740", 1, 0.6745),
    ("3981932", 2, 0.6601),
    ("2999394", 3, 0.6044),
    ("2002352", 4, 0.5879),
    ("2261600", 5, 0.5525),
    # Showcase 2: q="Blind SQL injection", lookup=pre_test
    ("4077800", 1, 0.7252),
    ("3896779", 2, 0.7081),
    ("3797662", 3, 0.7043),
    ("2830573", 4, 0.6863),
    ("2817658", 5, 0.6710),
    # Showcase 2: q="Blind SQL injection", lookup=mid_test
    ("3896779", 5, 0.5103),
    ("4077800", 1, 0.5286),
]

BANNED_WORDS = (
    "subagent",
    "TDD",
    "test-driven",
    "methodology",
    "implementer",
    "reviewer",
)


def _read_doc() -> str:
    assert DOC.exists(), "docs/showcases.md must exist"
    return DOC.read_text(encoding="utf-8")


def _showcase_blocks(doc: str) -> list[str]:
    parts = re.split(r"^## Showcase \d", doc, flags=re.M)
    assert len(parts) == 4, "doc must have exactly 3 showcases"
    return parts[1:]


def test_showcases_doc_has_three_showcases_with_all_sections():
    doc = _read_doc()
    required = (
        "### Target",
        "### Question",
        "### Steps",
        "### Evidence",
        "### Numbers",
        "### Limitations",
    )
    for block in _showcase_blocks(doc):
        for section in required:
            assert section in block, f"showcase missing {section}"
        assert "hackerone.com/reports/" in block, (
            "each showcase must link at least one real writeup")


def test_showcases_pinned_evidence_rows_are_in_doc():
    doc = _read_doc()
    for report_id, rank, score in PINNED_EVIDENCE:
        url = f"https://hackerone.com/reports/{report_id}"
        assert url in doc, f"doc must link {url}"
        assert f"{score:.4f}" in doc, (
            f"doc must record score {score:.4f} for {report_id}")
        assert f"| {rank} |" in doc, (
            f"doc must record rank {rank} in an evidence table")


def test_showcases_numbers_match_corpus_500_report():
    doc = _read_doc()
    report = REPORT.read_text(encoding="utf-8")
    # Aggregate numbers, measured on the real 500-row corpus.
    for needle in ("0.9048", "1.00", "0.714", "46.89", "78.45", "507"):
        assert needle in doc, f"doc must record {needle}"
    # Same numbers in the source report (comma decimals there).
    for needle in ("0,9048", "1,00", "0,714", "46,89", "78,45"):
        assert needle in report, f"report must record {needle}"
    assert round(19 / 21, 4) == 0.9048
    assert round(5 / 7, 3) == 0.714
    assert round(14 / 14, 2) == 1.00


def test_showcases_are_reproducible_from_the_doc():
    doc = _read_doc()
    for block in _showcase_blocks(doc):
        # A REST search request, or (install showcase) the doctor
        # command plus the MCP call it verifies.
        assert "/v1/search?q=" in block or (
            "eunoia doctor" in block and "search_writeups" in block
        ), "each showcase must give the exact request to re-run it"
    assert "lookup=mid_test" in doc, (
        "mid-test showcase must show the mid-test lookup parameter")
    assert "eunoia doctor" in doc, (
        "install showcase must show the doctor command")


def test_showcases_have_no_methodology_wording():
    doc = _read_doc()
    lowered = doc.lower()
    for word in BANNED_WORDS:
        assert word.lower() not in lowered, (
            f"product doc must not mention {word!r}")


def test_showcases_links_resolve_to_repo_files():
    doc = _read_doc()
    for rel in re.findall(r"\]\((docs/[^)\s]+)\)", doc):
        assert (REPO / rel).exists(), f"relative link must resolve: {rel}"
    for rel in re.findall(r"\]\((/v1/[^)\s]+)\)", doc):
        assert rel.startswith("/v1/"), f"API link must be a /v1 path: {rel}"
