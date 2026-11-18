"""Task 1: probe result must be recorded (no network in tests)."""

from pathlib import Path


def test_probe_result_recorded():
    doc = Path("docs/probes/hackerone-auth-2026-11-18.md").read_text()
    assert any(k in doc for k in ["no_auth_ok", "token_required", "plan_gated_403"])
    assert "GET /v1/hackers/hacktivity" in doc
