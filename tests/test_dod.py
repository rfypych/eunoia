"""Definition of Done checklist evidence (Rea-standard, plan section 4).

The checklist is docs/runbooks/dod-checklist.md: exactly 10 items
in the standard's order, every checked item carries measured
``Evidence:``, every unchecked item carries ``Reason:``. Items
that are not met are never checked by assertion: the 7-day poller
run (item 9) is unmet by construction until a deployment has
actually run 7 days, the DMCA email (item 8) is unmet until the
operator provides a real address, and the single PyPI install
command (item 1), the MCP Registry submission (item 4), and the
tagged release (item 10) are unmet for the stated reasons.
"""

from __future__ import annotations

import re
from pathlib import Path

# Repo-root relative: the tests must pass from any working
# directory, not only the repo root.
_REPO = Path(__file__).resolve().parent.parent
DOC = _REPO / "docs" / "runbooks" / "dod-checklist.md"
TRANSPARENCY = _REPO / "docs" / "transparency.md"


def _items(doc: str) -> list[tuple[bool, str]]:
    """(checked, body) for each DoD item, in order."""
    parts = re.split(r"^- \[(x| )\] ", doc, flags=re.MULTILINE)
    # parts[0] is the header; then alternating marker/body pairs.
    items = []
    for i in range(1, len(parts), 2):
        items.append((parts[i] == "x", parts[i + 1]))
    return items


def test_dod_checklist_complete():
    assert DOC.exists(), "docs/runbooks/dod-checklist.md is missing"
    items = _items(DOC.read_text())
    assert len(items) == 10, f"expected 10 DoD items, got {len(items)}"
    for n, (checked, body) in enumerate(items, start=1):
        if checked:
            assert "Evidence:" in body, f"item {n} is checked without Evidence:"
        else:
            assert "Reason:" in body, f"item {n} is unchecked without Reason:"
    # Item 1 is the one-command hosted install: unchecked, because
    # the single PyPI command does not work yet (not published).
    assert items[0][0] is False, "DoD 1 must stay unchecked (no PyPI release yet)"
    assert items[0][1].splitlines()[0].strip().startswith("1.")


def test_dod_checklist_poller_item_names_the_blocker():
    body = _items(DOC.read_text())[8][1]
    assert _items(DOC.read_text())[8][0] is False, (
        "DoD 9 (7-day poller) must stay unchecked")
    assert "7 days" in body or "7-day" in body
    assert "Reason:" in body


def test_dod_checklist_checked_items_cite_numbers():
    items = _items(DOC.read_text())
    for n, (checked, body) in enumerate(items, start=1):
        if checked:
            assert re.search(r"\d", body), (
                f"item {n} is checked but cites no measured number")


def test_transparency_documents_deviations():
    doc = TRANSPARENCY.read_text()
    assert "/v1/..." in doc
    assert "{url, notes?}" in doc
    assert "max 10" in doc


def test_transparency_states_what_does_not_exist_yet():
    doc = TRANSPARENCY.read_text()
    assert "none yet" in doc.lower()
    assert "dmca@eunoia.example" not in doc
    assert "not yet set" in doc.lower()
