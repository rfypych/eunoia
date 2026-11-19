"""Task 16: DoD checklist evidence (spec §7.4).

Deliberate deviation from the brief's verbatim test
(``doc.count("[x]") >= 10``): DoD 1 (poller ran 7 days unattended)
is a real time-span item and is NOT met — the poller has never run
7 days. At most 9 boxes can honestly be checked, so asserting 10
would be a fabricated claim. Step 3 of the brief ("anything
unmeasured stays ``[]`` with the reason") and the controller's
binding instruction (never check by invention) win over the
verbatim assertion. These tests assert the honest invariants
instead: exactly 10 items, every checked item carries measured
``Evidence:``, every unchecked item carries ``Reason:``, and item 1
is unchecked.
"""

from __future__ import annotations

import re
from pathlib import Path

# Repo-root relative (final review triage, Task 16): the tests must
# pass from any working directory, not only the repo root.
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
    # DoD 1 is the 7-day poller run: unmet by construction until a
    # deployment has actually run 7 days.
    assert items[0][0] is False, "DoD 1 must stay unchecked (no 7-day run yet)"
    assert items[0][1].splitlines()[0].strip().startswith("1.")


def test_dod_checklist_item1_names_the_blocker():
    body = _items(DOC.read_text())[0][1]
    assert "7 days" in body
    assert "Reason:" in body


def test_dod_checklist_checked_items_cite_numbers():
    items = _items(DOC.read_text())
    for n, (checked, body) in enumerate(items, start=1):
        if checked:
            assert re.search(r"\d", body), (
                f"item {n} is checked but cites no measured number")


def test_transparency_documents_r9_deviations():
    doc = TRANSPARENCY.read_text()
    assert "/v1/..." in doc
    assert "{url, notes?}" in doc
    assert "max 10" in doc


def test_transparency_states_what_does_not_exist_yet():
    doc = TRANSPARENCY.read_text()
    assert "none yet" in doc.lower()
    assert "dmca@eunoia.example" in doc
