"""Legal and release-basis files.

Pins the acceptance criteria: LICENSE MIT, SECURITY.md,
CONTRIBUTING.md and CHANGELOG.md exist; CHANGELOG records release
0.1.0 and an Unreleased section; the public docs contain no
placeholder wording; the takedown policy has no placeholder
contact. The DMCA agent email is a pending operator decision, not
something to invent: it is recorded as "not yet set" in the
transparency note and the takedown policy, and the literal
placeholder address appears nowhere in the repo's public docs.
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


def test_dmca_pending_item_recorded_without_placeholder_address():
    # The real address must not be invented anywhere, and the
    # placeholder string must not appear in any public doc. The
    # pending item is recorded as "not yet set".
    transparency = (_REPO / "docs" / "transparency.md").read_text()
    assert _PLACEHOLDER_EMAIL not in transparency
    assert "not yet set" in transparency.lower()
    for path in _CLEAN_DOCS:
        assert _PLACEHOLDER_EMAIL not in path.read_text(), (
            f"{path} presents the placeholder DMCA address")


def test_pyproject_declares_mit_license():
    with open(_REPO / "pyproject.toml", "rb") as f:
        project = tomllib.load(f)["project"]
    assert project.get("license") == {"text": "MIT"}
