"""T5 (Rea-standard): one-command hosted install — the ``eunoia`` CLI.

Meta-tests + unit tests, no database needed. They pin the T5 contract:

- Package name is ``eunoia-agents`` (``eunoia`` on PyPI is taken, checked
  2026-11-19: owned by another project; ``eunoia-agents`` returns 404),
  and the installed command is ``eunoia`` (free in PATH, checked same day).
- ``eunoia setup`` detects Claude Code, Codex and Cursor from a home
  directory, shows the planned change, asks for approval, writes the
  config with a backup, and is idempotent.
- ``eunoia doctor`` checks the hosted API and the hosted MCP server
  (``tools/list`` plus a real ``search_writeups`` call) with no local DB.
- ``eunoia update`` checks PyPI for a newer release and upgrades with
  the installer that put the package there.
- Config formats follow the vendors' docs checked 2026-11-19:
  Claude Code ``~/.claude.json`` needs ``"type": "http"`` next to ``url``;
  Codex ``~/.codex/config.toml`` uses ``[mcp_servers.eunoia]`` + ``url``;
  Cursor ``~/.cursor/mcp.json`` uses ``mcpServers`` + plain ``url``.
"""

from __future__ import annotations

import json
import textwrap
import tomllib
import urllib.error
from pathlib import Path

import pytest

from eunoia.cli import (
    HOSTED_API_URL,
    HOSTED_MCP_URL,
    PACKAGE_NAME,
    Change,
    apply_changes,
    check_update,
    check_update_status,
    detect_clients,
    doctor,
    main,
    planned_changes,
)

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _isolated_path(tmp_path, monkeypatch):
    # Detection also looks for client binaries on PATH, and this VM
    # ships a `codex` binary. Tests must see only what they install.
    bindir = tmp_path / "emptybin"
    bindir.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(bindir))


def test_package_name_is_eunoia_agents_and_command_is_eunoia():
    assert PACKAGE_NAME == "eunoia-agents"
    pyproject = (REPO / "pyproject.toml").read_text()
    assert 'name = "eunoia-agents"' in pyproject
    assert 'eunoia = "eunoia.cli:main"' in pyproject


def test_hosted_urls_are_the_live_box():
    assert HOSTED_API_URL == "http://129.150.57.82:10004"
    assert HOSTED_MCP_URL == "http://129.150.57.82:10005/mcp"


def test_base_install_is_lightweight_no_heavy_deps():
    # Fix T5/I1: the one-command hosted install must not bundle the
    # server's heavy dependencies (torch via sentence-transformers was
    # 24 min / 5.8 GB cold). The CLI is stdlib-only, so the base
    # install has no dependencies at all.
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    assert data["project"]["dependencies"] == []
    base = "\n".join(data["project"]["dependencies"])
    assert "torch" not in base and "sentence-transformers" not in base
    assert "sqlalchemy" not in base


def test_server_and_embed_extras_hold_heavy_deps():
    # Server deps are opt-in (server extra), embeddings are a
    # separate opt-in extra (embed) — installing the CLI must not
    # pull either of them.
    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    extras = data["project"]["optional-dependencies"]
    server = "\n".join(extras["server"])
    assert "sqlalchemy" in server and "fastapi" in server
    assert "sentence-transformers" not in server
    embed = "\n".join(extras["embed"])
    assert "sentence-transformers" in embed


def test_readme_documents_one_command_install():
    body = (REPO / "README.md").read_text()
    # Fix T5/I2: the command that works today (from a checkout) comes
    # first; `pipx install eunoia-agents` is documented only as the
    # command after the first PyPI release, not as a working step.
    assert "pip install ." in body
    assert "eunoia setup" in body
    assert "eunoia doctor" in body
    assert "pipx install eunoia-agents" in body
    assert body.index("pip install .") < body.index("pipx install eunoia-agents")
    assert "not on PyPI yet" in body


# --- detection -------------------------------------------------------------


def _fake_home(tmp_path: Path, *clients: str) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    if "claude" in clients:
        (home / ".claude.json").write_text(json.dumps({"projects": {}}))
    if "codex" in clients:
        (home / ".codex").mkdir()
        (home / ".codex" / "config.toml").write_text("")
    if "cursor" in clients:
        (home / ".cursor").mkdir()
    return home


def test_detect_clients_finds_all_three(tmp_path):
    home = _fake_home(tmp_path, "claude", "codex", "cursor")
    names = [c.name for c in detect_clients(home)]
    assert names == ["claude-code", "codex", "cursor"]


def test_detect_clients_finds_none_on_empty_home(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    assert detect_clients(home) == []


def test_detect_clients_by_binary_only(tmp_path, monkeypatch):
    # A client counts as installed when its binary is on PATH, even with
    # no config file yet.
    home = tmp_path / "home"
    home.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    codex = bindir / "codex"
    codex.write_text("#!/bin/sh\n")
    codex.chmod(0o755)
    monkeypatch.setenv("PATH", str(bindir))
    names = [c.name for c in detect_clients(home)]
    assert names == ["codex"]


# --- planning --------------------------------------------------------------


def test_planned_changes_create_configs(tmp_path):
    home = _fake_home(tmp_path, "claude", "codex", "cursor")
    changes = planned_changes(home, HOSTED_MCP_URL)
    assert len(changes) == 3
    # .claude.json and codex config.toml already exist in the fake home
    # (without an eunoia entry), so those are updates; Cursor's file
    # does not exist yet, so it is a create.
    assert {c.client_name: c.action for c in changes} == {
        "claude-code": "update",
        "codex": "update",
        "cursor": "create",
    }


def test_planned_changes_are_noop_when_already_configured(tmp_path):
    home = _fake_home(tmp_path, "claude", "codex", "cursor")
    apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    assert planned_changes(home, HOSTED_MCP_URL) == []


def test_planned_changes_update_stale_url(tmp_path):
    home = _fake_home(tmp_path, "claude")
    data = json.loads((home / ".claude.json").read_text())
    data["mcpServers"] = {"eunoia": {"type": "http", "url": "http://old:1234/mcp"}}
    (home / ".claude.json").write_text(json.dumps(data))
    changes = planned_changes(home, HOSTED_MCP_URL)
    assert len(changes) == 1 and changes[0].action == "update"


# --- apply -----------------------------------------------------------------


def test_apply_writes_all_three_configs(tmp_path):
    home = _fake_home(tmp_path, "claude", "codex", "cursor")
    written = apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    assert len(written) == 3
    claude = json.loads((home / ".claude.json").read_text())
    assert claude["mcpServers"]["eunoia"] == {
        "type": "http",
        "url": HOSTED_MCP_URL,
    }
    assert claude["projects"] == {}, "setup must preserve other keys"
    cursor = json.loads((home / ".cursor" / "mcp.json").read_text())
    assert cursor["mcpServers"]["eunoia"] == {"url": HOSTED_MCP_URL}
    codex = (home / ".codex" / "config.toml").read_text()
    assert '[mcp_servers.eunoia]' in codex
    assert f'url = "{HOSTED_MCP_URL}"' in codex


def test_apply_preserves_other_codex_servers(tmp_path):
    home = _fake_home(tmp_path, "codex")
    (home / ".codex" / "config.toml").write_text(
        '[mcp_servers.other]\nurl = "https://other.example/mcp"\n'
    )
    apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    codex = (home / ".codex" / "config.toml").read_text()
    assert 'url = "https://other.example/mcp"' in codex
    assert f'url = "{HOSTED_MCP_URL}"' in codex


def test_apply_backs_up_overwritten_config(tmp_path):
    home = _fake_home(tmp_path, "claude")
    original = (home / ".claude.json").read_text()
    data = json.loads(original)
    data["mcpServers"] = {"eunoia": {"type": "http", "url": "http://old:1234/mcp"}}
    (home / ".claude.json").write_text(json.dumps(data))
    apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    backup = home / ".claude.json.bak"
    assert backup.exists()
    assert json.loads(backup.read_text())["mcpServers"]["eunoia"]["url"] == (
        "http://old:1234/mcp"
    )


def test_apply_keeps_first_backup_and_timestamps_later_ones(tmp_path):
    # Fix T5/M4: a second setup must not silently overwrite the first
    # backup. The first backup stays at `.bak`; later ones are
    # timestamped so no earlier config is lost.
    home = _fake_home(tmp_path, "claude")
    first_before = (home / ".claude.json").read_text()
    apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    # Point the config at a different URL, then run setup again.
    data = json.loads((home / ".claude.json").read_text())
    data["mcpServers"]["eunoia"]["url"] = "http://other:9999/mcp"
    (home / ".claude.json").write_text(json.dumps(data))
    apply_changes(planned_changes(home, HOSTED_MCP_URL), yes=True)
    first_backup = home / ".claude.json.bak"
    assert first_backup.exists()
    assert first_backup.read_text() == first_before
    timestamped = sorted(home.glob(".claude.json.bak.*"))
    assert len(timestamped) == 1, f"expected one timestamped backup, got {timestamped}"
    assert json.loads(timestamped[0].read_text())["mcpServers"]["eunoia"][
        "url"
    ] == "http://other:9999/mcp"


def test_apply_refuses_without_approval(tmp_path):
    home = _fake_home(tmp_path, "claude")
    changes = planned_changes(home, HOSTED_MCP_URL)
    written = apply_changes(changes, yes=False, input_fn=lambda prompt: "n")
    assert written == []
    assert "mcpServers" not in (home / ".claude.json").read_text()


def test_apply_accepts_typed_yes(tmp_path):
    home = _fake_home(tmp_path, "claude")
    written = apply_changes(
        planned_changes(home, HOSTED_MCP_URL),
        yes=False,
        input_fn=lambda prompt: "y",
    )
    assert len(written) == 1


def test_apply_rejects_invalid_json_instead_of_clobbering(tmp_path):
    home = _fake_home(tmp_path, "claude")
    (home / ".claude.json").write_text("{not json")
    with pytest.raises(ValueError, match="invalid JSON"):
        planned_changes(home, HOSTED_MCP_URL)


# --- doctor ----------------------------------------------------------------


class _FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._body = body
        self.status = status

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _fake_opener_factory():
    # Mirrors the live server: plain JSON for tools/list, SSE for
    # tools/call is also accepted — both shapes are pinned by tests.
    def opener(request, timeout=10):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url.endswith("/v1/status"):
            return _FakeResponse(
                json.dumps(
                    {
                        "writeups_total": 50,
                        "writeups_active": 50,
                        "sources": [{"status": "ok", "consecutive_failures": 0}],
                    }
                ).encode()
            )
        if url.endswith("/mcp"):
            if b"tools/list" in request.data:
                return _FakeResponse(
                    json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": 1,
                            "result": {
                                "tools": [
                                    {"name": "search_writeups"},
                                    {"name": "get_writeup"},
                                    {"name": "get_writeup_skill"},
                                    {"name": "list_vuln_classes"},
                                    {"name": "list_programs"},
                                    {"name": "check_freshness"},
                                ]
                            },
                        }
                    ).encode()
                )
            return _FakeResponse(
                (
                    'event: message\ndata: {"jsonrpc": "2.0", "id": 2, "result": '
                    '{"content": [{"text": "{\\"results\\": [{\\"title\\": \\"x\\"}]}"}], '
                    '"isError": false}}\n\n'
                ).encode()
            )
        raise AssertionError(f"unexpected URL {url}")

    return opener


def test_doctor_reports_ok_against_fake_hosted():
    report = doctor(HOSTED_API_URL, HOSTED_MCP_URL, opener=_fake_opener_factory())
    assert report["api_ok"] is True
    assert report["api_writeups"] == 50
    assert report["mcp_ok"] is True
    assert report["mcp_tools"] == 6
    assert report["search_ok"] is True
    assert report["ok"] is True


def test_doctor_reports_failure_when_api_down():
    def opener(request, timeout=10):
        raise ConnectionError("refused")

    report = doctor(HOSTED_API_URL, HOSTED_MCP_URL, opener=opener)
    assert report["ok"] is False
    assert report["api_ok"] is False
    assert "refused" in report["api_error"]


def test_doctor_sends_mcp_name_header_for_tools_call():
    # The live server rejects tools/call with -32020 when the
    # Mcp-Name header does not match the tool name (verified 2026-11-19).
    seen: list[dict] = []

    def opener(request, timeout=10):
        seen.append(dict(request.headers))
        return _fake_opener_factory()(request, timeout=timeout)

    report = doctor(HOSTED_API_URL, HOSTED_MCP_URL, opener=opener)
    assert report["ok"] is True
    call_headers = [h for h in seen if h.get("Mcp-method") == "tools/call"]
    assert len(call_headers) == 1
    assert call_headers[0].get("Mcp-name") == "search_writeups"


# --- update ----------------------------------------------------------------


def test_check_update_reports_up_to_date():
    def fetcher(url, timeout=10):
        return {"info": {"version": "0.1.0"}}

    latest, needs_update = check_update("0.1.0", fetcher=fetcher)
    assert latest == "0.1.0" and needs_update is False


def test_check_update_reports_newer_available():
    def fetcher(url, timeout=10):
        return {"info": {"version": "0.2.0"}}

    latest, needs_update = check_update("0.1.0", fetcher=fetcher)
    assert latest == "0.2.0" and needs_update is True


def test_check_update_reports_not_published():
    def fetcher(url, timeout=10):
        raise ValueError("404")

    latest, needs_update = check_update("0.1.0", fetcher=fetcher)
    assert latest is None and needs_update is False


def test_check_update_status_distinguishes_404_from_unavailable():
    # Fix T5/M3: a 404 means "not published on PyPI yet"; a network
    # error or a 5xx means "could not reach PyPI" — the two must not
    # be reported the same way.
    def not_found(url, timeout=10):
        raise ValueError("404")

    latest, needs_update, status = check_update_status("0.1.0", fetcher=not_found)
    assert (latest, needs_update, status) == (None, False, "not_published")

    def server_error(url, timeout=10):
        raise urllib.error.HTTPError(url, 500, "Server Error", {}, None)

    latest, needs_update, status = check_update_status("0.1.0", fetcher=server_error)
    assert (latest, needs_update, status) == (None, False, "unavailable")

    def no_network(url, timeout=10):
        raise urllib.error.URLError("refused")

    latest, needs_update, status = check_update_status("0.1.0", fetcher=no_network)
    assert (latest, needs_update, status) == (None, False, "unavailable")


def test_main_update_not_published_is_known_state(monkeypatch, capsys):
    # 404: known state, exit 0, and the message must point at the
    # checkout install that works today, not at a PyPI command.
    import eunoia.cli as cli_mod

    monkeypatch.setattr(
        cli_mod, "_pypi_fetcher", lambda url, timeout=10: (_ for _ in ()).throw(ValueError("404"))
    )
    assert main(["update"]) == 0
    out = capsys.readouterr().out
    assert "not published on PyPI yet" in out
    assert "pip install ." in out


def test_main_update_unavailable_exits_nonzero(monkeypatch, capsys):
    # 5xx / network failure: not a known state, exit non-zero and say
    # PyPI could not be reached instead of claiming "not published".
    import eunoia.cli as cli_mod

    def failing(url, timeout=10):
        raise urllib.error.HTTPError(url, 503, "Unavailable", {}, None)

    monkeypatch.setattr(cli_mod, "_pypi_fetcher", failing)
    assert main(["update"]) == 1
    out = capsys.readouterr().out
    assert "Could not reach PyPI" in out


# --- main ------------------------------------------------------------------


def test_main_doctor_exit_code(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("eunoia.cli._default_opener", _fake_opener_factory())
    assert main(["doctor"]) == 0
    assert "OK" in capsys.readouterr().out


def test_main_setup_no_clients_exits_nonzero(tmp_path, monkeypatch, capsys):
    home = tmp_path / "home"
    home.mkdir()
    assert main(["setup", "--home", str(home), "--yes"]) == 1
    assert "No supported agent detected" in capsys.readouterr().out


def test_main_setup_dry_run_writes_nothing(tmp_path):
    home = _fake_home(tmp_path, "cursor")
    assert main(["setup", "--home", str(home), "--dry-run"]) == 0
    assert not (home / ".cursor" / "mcp.json").exists()


def test_main_version():
    assert main(["--version"]) == 0
