"""Task 1: probe result must be recorded (no network in tests)."""

import importlib.util
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "probe_hackerone",
    Path(__file__).resolve().parent.parent / "scripts" / "probe_hackerone.py",
)
_probe = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_probe)
classify = _probe.classify


def test_probe_result_recorded():
    # Repo-root relative (final review triage, Task 1): the test must
    # pass from any working directory, not only the repo root.
    repo = Path(__file__).resolve().parent.parent
    doc = (repo / "docs" / "probes" / "hackerone-auth-2026-11-18.md").read_text()
    assert any(k in doc for k in ["no_auth_ok", "token_required", "plan_gated_403"])
    assert "GET /v1/hackers/hacktivity" in doc


def test_classify_token_required_only_for_401():
    assert classify(401, "") == "token_required"


def test_classify_known_outcomes():
    assert classify(200, "") == "no_auth_ok"
    assert classify(403, "") == "plan_gated_403"


def test_classify_429_5xx_and_network_failure_are_probe_failed():
    for status in (0, 429, 500, 502, 503):
        assert classify(status, "") == "probe_failed", f"status {status} must not be token_required"


def test_probe_null_data_body_does_not_crash(monkeypatch, tmp_path):
    """Final review triage, Task 1: a 200 body of '{"data": null}'
    crashed the probe with TypeError (None is not iterable)."""
    import json as _json

    monkeypatch.setattr(
        _probe, "probe", lambda: (200, _json.dumps({"data": None})))
    doc_path = tmp_path / "probe-null-data-test.md"
    monkeypatch.setattr(_probe, "DOC_PATH", doc_path)
    _probe.main()
    doc = doc_path.read_text()
    assert "no_auth_ok" in doc
    assert "Items returned: `0`" in doc

