"""T8 (Rea-standard): MCP discoverable — config files, plugin, registry.

Meta-tests, no database needed. They pin the T8 acceptance criteria:

- ``mcp.json`` at the repo root and per-client configs under
  ``clients/`` (Claude Code, Codex, Cursor) all point at the hosted
  MCP server, with the transport format each vendor documents
  (checked 2026-11-19): Claude Code needs ``"type": "http"`` next to
  ``url``; Codex uses ``[mcp_servers.eunoia]`` + ``url`` in TOML;
  Cursor uses ``mcpServers`` + plain ``url``.
- ``server.json`` follows the official MCP Registry schema
  (``2025-12-11``, fetched and read 2026-11-19): reverse-DNS name
  ``io.github.rfypych/eunoia``, description 1-100 chars, exact
  version matching ``pyproject.toml``, and a ``remotes`` entry of type
  ``streamable-http`` pointing at the hosted server. No ``packages``
  entry: the PyPI package is not published yet, and the registry
  rejects a package entry it cannot find at publish time.
- The Claude Code plugin under ``plugins/claude-code/`` has a
  manifest (``.claude-plugin/plugin.json``) whose ``mcpServers``
  points at the plugin's ``.mcp.json``, which carries the same
  hosted entry.
- What ``eunoia setup`` writes for a fresh home matches the repo's
  client files exactly, so the files and the CLI cannot drift apart.
- Registry status is honest: ``docs/mcp.md`` records that the server
  has NOT been submitted to the Official MCP Registry (checked live
  2026-11-19: search count 0, direct lookup 404), and the README
  does not claim a listing. Submission needs the operator's
  identity decision, so it is recorded as blocked, not done.
- The README MCP section points at these files instead of calling
  the work "planned".
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from eunoia.cli import (
    HOSTED_MCP_URL,
    apply_changes,
    planned_changes,
)

_REPO = Path(__file__).resolve().parent.parent

_SCHEMA_URL = (
    "https://static.modelcontextprotocol.io/schemas/"
    "2025-12-11/server.schema.json"
)
_REGISTRY_NAME = "io.github.rfypych/eunoia"
_VERSION_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_NAME_RE = re.compile(r"^[a-zA-Z0-9.-]+/[a-zA-Z0-9._-]+$")


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text())


def test_mcp_json_points_at_hosted_server():
    data = _load_json(_REPO / "mcp.json")
    entry = data["mcpServers"]["eunoia"]
    assert entry["type"] == "http"
    assert entry["url"] == HOSTED_MCP_URL


def test_server_json_follows_registry_schema():
    data = _load_json(_REPO / "server.json")
    assert data["$schema"] == _SCHEMA_URL
    assert data["name"] == _REGISTRY_NAME
    assert _NAME_RE.match(data["name"]), data["name"]
    assert 1 <= len(data["description"]) <= 100, (
        f"description is {len(data['description'])} chars, "
        "schema allows at most 100")
    version = data["version"]
    assert _VERSION_RE.match(version), (
        f"version {version!r} is not an exact version")
    assert "packages" not in data, (
        "packages entry would fail registry publish: the PyPI "
        "package is not published yet")
    assert data["remotes"] == [
        {"type": "streamable-http", "url": HOSTED_MCP_URL}
    ]
    assert data["repository"]["url"] == (
        "https://github.com/rfypych/eunoia")
    assert data["repository"]["source"] == "github"


def test_server_json_version_matches_pyproject():
    import tomllib as _tomllib

    project = _tomllib.loads((_REPO / "pyproject.toml").read_text())
    server = _load_json(_REPO / "server.json")
    assert server["version"] == project["project"]["version"]


def test_client_configs_point_at_hosted_server():
    claude = _load_json(_REPO / "clients" / "claude-code" / ".mcp.json")
    assert claude["mcpServers"]["eunoia"] == {
        "type": "http", "url": HOSTED_MCP_URL}

    codex = tomllib.loads(
        (_REPO / "clients" / "codex" / "config.toml").read_text())
    assert codex["mcp_servers"]["eunoia"]["url"] == HOSTED_MCP_URL

    cursor = _load_json(_REPO / "clients" / "cursor" / "mcp.json")
    assert cursor["mcpServers"]["eunoia"] == {"url": HOSTED_MCP_URL}


def test_claude_code_plugin_manifest_and_config():
    plugin = _load_json(
        _REPO / "plugins" / "claude-code" / ".claude-plugin"
        / "plugin.json")
    assert plugin["name"] == "eunoia"
    assert _VERSION_RE.match(plugin["version"])
    assert plugin["mcpServers"] == "./.mcp.json"
    mcp = _load_json(_REPO / "plugins" / "claude-code" / ".mcp.json")
    assert mcp["mcpServers"]["eunoia"] == {
        "type": "http", "url": HOSTED_MCP_URL}


def test_setup_writes_match_repo_client_files(tmp_path):
    home = tmp_path / "home"
    for rel in (".claude", ".codex", ".cursor"):
        (home / rel).mkdir(parents=True)
    written = apply_changes(
        planned_changes(home, HOSTED_MCP_URL), yes=True)
    assert len(written) == 3
    by_name = {p.name: json.loads(p.read_text()) for p in written
               if p.suffix == ".json"}
    assert by_name[".claude.json"]["mcpServers"] == _load_json(
        _REPO / "clients" / "claude-code" / ".mcp.json")["mcpServers"]
    assert by_name["mcp.json"]["mcpServers"] == _load_json(
        _REPO / "clients" / "cursor" / "mcp.json")["mcpServers"]
    codex = tomllib.loads(
        (home / ".codex" / "config.toml").read_text())
    assert codex["mcp_servers"]["eunoia"]["url"] == HOSTED_MCP_URL


def test_registry_status_is_honest_not_submitted():
    doc = (_REPO / "docs" / "mcp.md").read_text()
    assert "not submitted" in doc.lower()
    lowered = doc.lower()
    assert "listed in the official mcp registry" not in lowered
    assert "registered in the official mcp registry" not in lowered
    assert "io.github.rfypych/eunoia" in doc
    assert "mcp.json" in doc and "server.json" in doc


def test_readme_mcp_section_points_at_config_files():
    readme = (_REPO / "README.md").read_text()
    assert "planned work, not done yet" not in readme
    assert "mcp.json" in readme
    assert "server.json" in readme
    assert "docs/mcp.md" in readme
