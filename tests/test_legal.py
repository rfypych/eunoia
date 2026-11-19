"""Task T3 (Rea-standard): legal and release-basis files.

Pins the T3 acceptance criteria: LICENSE MIT, SECURITY.md,
CONTRIBUTING.md and CHANGELOG.md exist; CHANGELOG records release
0.1.0 and an Unreleased section; the new public docs contain no
placeholder wording; the takedown policy no longer presents the
placeholder address as a contact. The literal placeholder address
is deliberately kept in exactly one designated place — the open-items
list in docs/transparency.md (also pinned by tests/test_dod.py) —
because the real DMCA agent email is a pending operator decision,
not something this task may invent.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent

_NEW_DOCS = [
    _REPO / "LICENSE",
    _REPO / "SECURITY.md",
    _REPO / "CONTRIBUTING.md",
    _REPO / "CHANGELOG.md",
]

# Public docs that must be free of placeholder wording after T3.
_CLEAN_DOCS = _NEW_DOCS + [
    _REPO / "docs" / "policies" / "takedown.md",
    _REPO / "docs" / "runbook.md",
]

_PLACEHOLDER_EMAIL = "dmca@eunoia.example"


def test_license_mit_exists():
    lic = _REPO / "LICENSE"
    assert lic.exists(), "LICENSE is missing"
    text = lic.read_text()
    assert "MIT License" in text
    assert "2026" in text
    assert "Permission is hereby granted, free of charge" in text


def test_security_and_contributing_exist():
    for path in (_REPO / "SECURITY.md", _REPO / "CONTRIBUTING.md"):
        assert path.exists(), f"{path.name} is missing"
        assert len(path.read_text().splitlines()) >= 10, (
            f"{path.name} is suspiciously short")


def test_changelog_records_0_1_0_and_unreleased():
    text = (_REPO / "CHANGELOG.md").read_text()
    assert "## [Unreleased]" in text
    assert "## [0.1.0]" in text
    assert "2026-11-19" in text


def test_new_docs_contain_no_placeholder_wording():
    for path in _CLEAN_DOCS:
        text = path.read_text()
        assert "placeholder" not in text.lower(), (
            f"{path} still contains 'placeholder'")
        assert "example" not in text.lower(), (
            f"{path} still contains 'example'")


def test_takedown_policy_has_no_placeholder_contact():
    text = (_REPO / "docs" / "policies" / "takedown.md").read_text()
    assert _PLACEHOLDER_EMAIL not in text
    assert "not yet set" in text.lower()


def test_dmca_pending_item_kept_in_designated_list_only():
    # The designated user-task list: transparency.md open items.
    # The real address must not be invented anywhere, and the
    # placeholder string must not leak into any other public doc.
    transparency = (_REPO / "docs" / "transparency.md").read_text()
    assert _PLACEHOLDER_EMAIL in transparency
    for path in _CLEAN_DOCS:
        assert _PLACEHOLDER_EMAIL not in path.read_text(), (
            f"{path} presents the placeholder DMCA address")


def test_pyproject_declares_mit_license():
    with open(_REPO / "pyproject.toml", "rb") as f:
        project = tomllib.load(f)["project"]
    assert project.get("license") == {"text": "MIT"}
