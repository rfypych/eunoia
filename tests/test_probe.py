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
    doc = Path("docs/probes/hackerone-auth-2026-11-18.md").read_text()
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

