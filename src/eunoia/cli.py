"""The ``eunoia`` command-line client (T5, Rea-standard).

One-command hosted install, once the package is on PyPI:
``pipx install eunoia-agents`` puts this command on PATH. Until the
first PyPI release (blocked on the branch being pushed and the package
being published), install from a checkout instead: ``pip install .``.
The client talks to the hosted Eunoia API/MCP server and needs no
local database — that is the point: the agent's brain lives on the
server, the client only wires the agent to it.

Subcommands:

- ``eunoia setup`` — detect Claude Code, Codex and Cursor, show the
  config change, ask for approval, write it with a backup.
- ``eunoia doctor`` — check the hosted API (``/v1/status``) and the
  hosted MCP server (``tools/list`` plus a real ``search_writeups`` call).
- ``eunoia update`` — check PyPI for a newer ``eunoia-agents`` release
  and upgrade with the installer that installed it.
- ``eunoia skills install`` — install the registry skill plus one
  per-class skill per real vuln class into each detected agent's
  skills directory. The skills are file-based and work over the REST
  API alone: no MCP server and no local database are needed to use
  them. MCP is only an alternative transport for the per-writeup
  skill, never a requirement.
- ``eunoia skills list`` — list installed Eunoia skills per agent.

Skill directories follow the vendors' docs checked 2026-11-19:

- Claude Code: ``~/.claude/skills/<name>/SKILL.md`` (personal).
- Codex: ``~/.agents/skills/<name>/SKILL.md`` (personal; the older
  ``~/.codex/skills`` is still read but no longer documented).
- Cursor: ``~/.cursor/skills/<name>/SKILL.md`` (personal; Cursor also
  reads ``.claude/skills`` and ``.agents/skills``).

This module uses only the standard library on purpose: importing it must
never pull in the server's heavy dependencies (SQLAlchemy, torch), so a
fresh ``pipx install`` can run ``eunoia doctor`` without a database.

Config formats follow the vendors' docs checked 2026-11-19:

- Claude Code: ``~/.claude.json``, ``mcpServers`` entry needs
  ``"type": "http"`` next to ``url`` (an entry with ``url`` but no
  ``type`` is read as stdio and skipped).
- Codex: ``~/.codex/config.toml``, ``[mcp_servers.eunoia]`` + ``url``.
- Cursor: ``~/.cursor/mcp.json``, ``mcpServers`` + plain ``url``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib import metadata, resources
from pathlib import Path
from typing import Callable

__version__ = "0.1.0"
PACKAGE_NAME = "eunoia-agents"
PYPI_URL = f"https://pypi.org/pypi/{PACKAGE_NAME}/json"

HOSTED_API_URL = os.environ.get("EUNOIA_API_URL", "http://129.150.57.82:10004")
HOSTED_MCP_URL = os.environ.get("EUNOIA_MCP_URL", "http://129.150.57.82:10005/mcp")

# MCP spec revision the hosted server speaks (stateless, no initialize).
MCP_PROTOCOL_VERSION = "2026-07-28"
EXPECTED_TOOLS = {
    "search_writeups",
    "get_writeup",
    "get_writeup_skill",
    "list_vuln_classes",
    "list_programs",
    "check_freshness",
}

__all__ = [
    "HOSTED_API_URL",
    "HOSTED_MCP_URL",
    "PACKAGE_NAME",
    "Change",
    "SkillFile",
    "SkillInstall",
    "apply_changes",
    "apply_skill_installs",
    "check_update",
    "check_update_status",
    "detect_clients",
    "doctor",
    "fetch_skills",
    "list_installed_skills",
    "main",
    "plan_skill_installs",
    "planned_changes",
]


# ---------------------------------------------------------------------------
# Client definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Client:
    """One supported agent client and where it keeps MCP servers."""

    name: str  # claude-code, codex, cursor
    display: str
    binary: str
    config_rel: str  # path under the home directory
    home_dir_rel: str  # dedicated dir under home, if the client has one
    kind: str  # json-claude | toml-codex | json-cursor


CLIENTS = (
    Client("claude-code", "Claude Code", "claude", ".claude.json", ".claude", "json-claude"),
    Client("codex", "Codex", "codex", ".codex/config.toml", ".codex", "toml-codex"),
    Client("cursor", "Cursor", "cursor", ".cursor/mcp.json", ".cursor", "json-cursor"),
)


def _client_entry(client: Client, mcp_url: str) -> dict:
    """The MCP server entry this client expects."""
    if client.kind == "json-cursor":
        return {"url": mcp_url}
    return {"type": "http", "url": mcp_url}


def detect_clients(home: Path) -> list[Client]:
    """Clients installed in ``home``: binary on PATH, or config/dir present."""
    found = []
    for client in CLIENTS:
        config = home / client.config_rel
        if (
            shutil.which(client.binary) is not None
            or config.exists()
            or (home / client.home_dir_rel).exists()
        ):
            found.append(client)
    return found


# ---------------------------------------------------------------------------
# Planning: what ``setup`` would write, before it writes anything
# ---------------------------------------------------------------------------


@dataclass
class Change:
    """One config file ``setup`` will create or update."""

    path: Path
    client_name: str
    action: str  # "create" | "update"
    before: str | None
    after: str


def _json_config_after(path: Path, client: Client, mcp_url: str) -> str | None:
    """Desired file text for a JSON client, or None when already correct."""
    if path.exists():
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path}: invalid JSON: top level is not an object")
    else:
        data = {}
    servers = data.setdefault("mcpServers", {})
    if not isinstance(servers, dict):
        raise ValueError(f"{path}: invalid JSON: 'mcpServers' is not an object")
    entry = _client_entry(client, mcp_url)
    if servers.get("eunoia") == entry:
        return None
    servers["eunoia"] = entry
    return json.dumps(data, indent=2) + "\n"


def _upsert_codex_toml(text: str, mcp_url: str) -> str:
    """Return ``text`` with ``[mcp_servers.eunoia] url = ...`` set."""
    header = "[mcp_servers.eunoia]"
    url_line = f'url = "{mcp_url}"'
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.strip() == header:
            j = i + 1
            while j < len(lines) and not lines[j].startswith("["):
                if lines[j].strip().startswith("url"):
                    lines[j] = url_line
                    return "\n".join(lines) + "\n"
                j += 1
            lines.insert(j, url_line)
            return "\n".join(lines) + "\n"
    if text and not text.endswith("\n"):
        text += "\n"
    return text + f"\n{header}\n{url_line}\n"


def _codex_config_after(path: Path, mcp_url: str) -> str | None:
    """Desired file text for Codex, or None when already correct."""
    text = path.read_text() if path.exists() else ""
    if text:
        try:
            parsed = tomllib.loads(text)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"{path}: invalid TOML: {exc}") from exc
        server = (parsed.get("mcp_servers") or {}).get("eunoia") or {}
        if server.get("url") == mcp_url:
            return None
    return _upsert_codex_toml(text, mcp_url)


def planned_changes(home: Path, mcp_url: str) -> list[Change]:
    """The config writes ``setup`` would make, in client order."""
    changes: list[Change] = []
    for client in detect_clients(home):
        path = home / client.config_rel
        before = path.read_text() if path.exists() else None
        if client.kind == "toml-codex":
            after = _codex_config_after(path, mcp_url)
        else:
            after = _json_config_after(path, client, mcp_url)
        if after is None:
            continue
        changes.append(
            Change(
                path=path,
                client_name=client.name,
                action="create" if before is None else "update",
                before=before,
                after=after,
            )
        )
    return changes


def _backup_path(path: Path) -> Path:
    """Backup path for ``path`` without overwriting an earlier backup.

    The first backup is ``<path>.bak``; later ones are timestamped
    (``<path>.bak.YYYYMMDD-HHMMSS``, with a counter if the same second
    is hit twice), so a second ``setup`` never silently destroys the
    config the first ``setup`` saved.
    """
    first = Path(str(path) + ".bak")
    if not first.exists():
        return first
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    candidate = Path(f"{path}.bak.{stamp}")
    counter = 2
    while candidate.exists():
        candidate = Path(f"{path}.bak.{stamp}-{counter}")
        counter += 1
    return candidate


def apply_changes(
    changes: list[Change],
    *,
    yes: bool = False,
    input_fn: Callable[[str], str] = input,
) -> list[Path]:
    """Write ``changes`` after approval; return the files written."""
    if not changes:
        return []
    for change in changes:
        print(f"  {change.client_name}: {change.action} {change.path}")
    if not yes:
        answer = input_fn("Apply these changes? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted: no changes applied.")
            return []
    written: list[Path] = []
    for change in changes:
        if change.action == "update" and change.before is not None:
            backup = _backup_path(change.path)
            backup.write_text(change.before)
            print(f"  backup: {backup}")
        change.path.parent.mkdir(parents=True, exist_ok=True)
        change.path.write_text(change.after)
        written.append(change.path)
    return written


# ---------------------------------------------------------------------------
# Doctor: is the hosted service reachable and answering?
# ---------------------------------------------------------------------------


def _default_opener(request, timeout=10):
    return urllib.request.urlopen(request, timeout=timeout)


def _http_json(opener, url: str, timeout: int = 10) -> dict:
    with opener(urllib.request.Request(url), timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _mcp_rpc(opener, mcp_url: str, method: str, params: dict, timeout=10, name=None) -> dict:
    """One stateless MCP call over Streamable HTTP; return its ``result``.

    The hosted server enforces the ``Mcp-Name`` header for ``tools/call``
    (verified live 2026-11-19: without it the server answers -32020,
    "mcp-name header does not match the request body's 'name' parameter").
    """
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": MCP_PROTOCOL_VERSION,
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
        "Mcp-Method": method,
    }
    if name is not None:
        headers["Mcp-Name"] = name
    request = urllib.request.Request(
        mcp_url,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with opener(request, timeout=timeout) as resp:
        body = resp.read().decode("utf-8")
    # The hosted server answers plain JSON (verified live 2026-11-19);
    # some MCP servers answer SSE instead, so accept both shapes.
    try:
        message = json.loads(body)
    except json.JSONDecodeError:
        message = None
    if isinstance(message, dict):
        if "result" in message:
            return message["result"]
        if "error" in message:
            raise ValueError(f"MCP error: {message['error']}")
    for line in body.splitlines():
        if not line.startswith("data:"):
            continue
        message = json.loads(line[len("data:"):].strip())
        if "result" in message:
            return message["result"]
        if "error" in message:
            raise ValueError(f"MCP error: {message['error']}")
    raise ValueError("MCP response contained no result")


def _search_text_ok(result: dict) -> bool:
    """True when a ``search_writeups`` call returned a real result."""
    if result.get("isError"):
        return False
    content = result.get("content") or []
    if not content or not content[0].get("text"):
        return False
    try:
        parsed = json.loads(content[0]["text"])
    except (json.JSONDecodeError, TypeError):
        return bool(content[0]["text"].strip())
    results = parsed.get("results") if isinstance(parsed, dict) else None
    return isinstance(results, list) and len(results) > 0


def doctor(
    api_url: str = HOSTED_API_URL,
    mcp_url: str = HOSTED_MCP_URL,
    opener=None,
) -> dict:
    """Check the hosted API and MCP server; never touches a local DB."""
    opener = opener or _default_opener
    report: dict = {
        "ok": False,
        "api_ok": False,
        "api_writeups": None,
        "api_error": None,
        "mcp_ok": False,
        "mcp_tools": None,
        "mcp_tool_names": [],
        "search_ok": False,
        "search_error": None,
    }
    try:
        status = _http_json(opener, api_url.rstrip("/") + "/v1/status")
    except Exception as exc:  # network, HTTP error, bad JSON: all "down"
        report["api_error"] = str(exc)
        return report
    sources = status.get("sources") or []
    report["api_writeups"] = status.get("writeups_active")
    report["api_ok"] = bool(
        status.get("writeups_active")
        and all(s.get("status") == "ok" for s in sources)
    )
    if not report["api_ok"]:
        report["api_error"] = "source status is not ok"
        return report
    try:
        result = _mcp_rpc(opener, mcp_url, "tools/list", {})
        names = [t["name"] for t in result.get("tools", [])]
        report["mcp_tool_names"] = names
        report["mcp_tools"] = len(names)
        report["mcp_ok"] = EXPECTED_TOOLS.issubset(set(names))
        call = _mcp_rpc(
            opener,
            mcp_url,
            "tools/call",
            {"name": "search_writeups", "arguments": {"query": "CSRF", "limit": 1}},
            name="search_writeups",
        )
        report["search_ok"] = _search_text_ok(call)
        if not report["search_ok"]:
            report["search_error"] = "search_writeups returned no results"
    except Exception as exc:
        report["search_error"] = str(exc)
        return report
    report["ok"] = bool(
        report["api_ok"] and report["mcp_ok"] and report["search_ok"]
    )
    return report


# ---------------------------------------------------------------------------
# Update: is there a newer release on PyPI?
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Skills: installable SKILL.md files (T9)
# ---------------------------------------------------------------------------

# Personal skills directory per client, relative to home. Paths checked
# against vendor docs 2026-11-19 (see module docstring).
SKILL_DIR_REL = {
    "claude-code": ".claude/skills",
    "codex": ".agents/skills",
    "cursor": ".cursor/skills",
}

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_BAD_LINK_RES = ("javascript:", "data:text/html", "data:application")


@dataclass(frozen=True)
class SkillFile:
    """One installable skill: its directory name and SKILL.md text."""

    name: str
    text: str


@dataclass
class SkillInstall:
    """One SKILL.md file ``skills install`` will create or update."""

    path: Path
    skill_name: str
    client_name: str
    action: str  # "create" | "update"
    before: str | None
    text: str


def _packaged_registry_skill() -> str:
    """The registry skill shipped as package data (no network needed)."""
    return (
        resources.files("eunoia.skills_data") / "eunoia-registry" / "SKILL.md"
    ).read_text(encoding="utf-8")


def _parse_skill_frontmatter(text: str) -> tuple[str, str]:
    """Return ``(name, description)`` from a SKILL.md, or raise ValueError."""
    lines = text.splitlines()
    if len(lines) < 3 or lines[0].strip() != "---":
        raise ValueError("skill has no frontmatter: expected '---' first line")
    try:
        end = lines.index("---", 1)
    except ValueError:
        raise ValueError("skill frontmatter is not closed") from None
    fields: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        fields[key.strip()] = value.strip()
    name = fields.get("name", "")
    description = fields.get("description", "")
    if not _NAME_RE.match(name):
        raise ValueError(f"skill has an invalid name: {name!r}")
    if not description or len(description) > 1024:
        raise ValueError(
            "skill has a missing or over-long description "
            "(must be 1-1024 characters)"
        )
    return name, description


def _validate_skill_text(text: str) -> str:
    """Validate a fetched SKILL.md; return its skill name.

    A skill that reaches an agent's disk must be safe to follow: valid
    frontmatter and no non-http(s) link (a ``javascript:`` or ``data:``
    link in a skill would run when the agent follows it — the T6
    review's M1, applied here at install time).
    """
    name, _description = _parse_skill_frontmatter(text)
    lowered = text.lower()
    for bad in _BAD_LINK_RES:
        if bad in lowered:
            raise ValueError(
                f"skill {name!r} contains a non-http(s) link ({bad})"
            )
    return name


def _http_text(opener, url: str, timeout: int = 10) -> str:
    with opener(urllib.request.Request(url), timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def fetch_skills(
    api_url: str = HOSTED_API_URL,
    opener=None,
    classes: list[str] | None = None,
) -> list[SkillFile]:
    """Fetch the installable skill set: registry skill + one per class.

    The registry skill is packaged (no network). Per-class skills are
    fetched live from ``GET /v1/vuln-classes/{class}/skill.md``, so an
    install always gets the current aggregate, never a stale copy.
    ``unclassified`` is never installed: there is no technique to teach
    for a class that means "not yet classified".
    """
    opener = opener or _default_opener
    skills = [SkillFile("writeup-registry", _packaged_registry_skill())]
    if classes is None:
        data = _http_json(opener, api_url.rstrip("/") + "/v1/vuln-classes")
        classes = [item["vuln_class"] for item in data.get("items", [])]
    for vuln_class in classes:
        if vuln_class.strip().lower() == "unclassified":
            continue
        url = (
            api_url.rstrip("/")
            + "/v1/vuln-classes/"
            + urllib.parse.quote(vuln_class, safe="")
            + "/skill.md"
        )
        text = _http_text(opener, url)
        skills.append(SkillFile(_validate_skill_text(text), text))
    return skills


def plan_skill_installs(
    home: Path,
    skills: list[SkillFile],
    clients: list[Client] | None = None,
) -> list[SkillInstall]:
    """The SKILL.md writes ``skills install`` would make, in client order.

    Only detected agents get skills. When no agent is detected at all,
    fall back to the Claude Code layout (``~/.claude/skills``), which
    Cursor also reads, plus the Codex layout (``~/.agents/skills``),
    and say so — installing nothing would leave the user with no
    usable skill at all.
    """
    if clients is None:
        clients = detect_clients(home)
    if not clients:
        clients = [c for c in CLIENTS if c.name in ("claude-code", "codex")]
    installs: list[SkillInstall] = []
    for client in clients:
        base = home / SKILL_DIR_REL[client.name]
        for skill in skills:
            path = base / skill.name / "SKILL.md"
            before = path.read_text() if path.exists() else None
            if before == skill.text:
                continue
            installs.append(
                SkillInstall(
                    path=path,
                    skill_name=skill.name,
                    client_name=client.name,
                    action="create" if before is None else "update",
                    before=before,
                    text=skill.text,
                )
            )
    return installs


def apply_skill_installs(
    installs: list[SkillInstall],
    *,
    yes: bool = False,
    input_fn: Callable[[str], str] | None = None,
) -> list[Path]:
    """Write ``installs`` after approval; return the files written.

    ``input_fn`` defaults to :func:`input` resolved at call time, so
    callers (and tests) can replace ``builtins.input``.
    """
    if not installs:
        return []
    if input_fn is None:
        input_fn = input
    for install in installs:
        print(f"  {install.client_name}: {install.action} {install.path}")
    if not yes:
        answer = input_fn("Install these skills? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Aborted: no changes applied.")
            return []
    written: list[Path] = []
    for install in installs:
        if install.action == "update" and install.before is not None:
            backup = _backup_path(install.path)
            backup.write_text(install.before)
            print(f"  backup: {backup}")
        install.path.parent.mkdir(parents=True, exist_ok=True)
        install.path.write_text(install.text)
        written.append(install.path)
    return written


def list_installed_skills(
    home: Path,
    clients: list[Client] | None = None,
) -> dict[str, list[str]]:
    """Installed Eunoia skills per detected client (empty when none)."""
    if clients is None:
        clients = detect_clients(home)
    found: dict[str, list[str]] = {}
    for client in clients:
        base = home / SKILL_DIR_REL[client.name]
        if not base.exists():
            continue
        names = sorted(
            p.name
            for p in base.iterdir()
            if p.is_dir() and (p / "SKILL.md").is_file()
        )
        if names:
            found[client.name] = names
    return found


def _pypi_fetcher(url: str, timeout: int = 10) -> dict:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise ValueError(f"{exc.code}") from exc


def _version_tuple(version: str) -> tuple[int, ...]:
    parts = []
    for piece in re.split(r"[.\-+]", version):
        try:
            parts.append(int(piece))
        except ValueError:
            break
    return tuple(parts) or (0,)


def _classify_pypi_error(exc: Exception) -> str:
    """``"not_published"`` for a PyPI 404, ``"unavailable"`` otherwise.

    A 404 means the package is not on PyPI yet; a network error or a
    5xx means PyPI could not be reached. The two must not be reported
    the same way: one is a known state, the other is a transient
    failure. ``_pypi_fetcher`` turns an HTTP error into
    ``ValueError("<code>")``, so a bare ``"404"`` counts as well.
    """
    if isinstance(exc, urllib.error.HTTPError):
        return "not_published" if exc.code == 404 else "unavailable"
    if isinstance(exc, ValueError) and str(exc).strip() == "404":
        return "not_published"
    return "unavailable"


def check_update_status(
    installed_version: str, fetcher=None
) -> tuple[str | None, bool, str]:
    """Return ``(latest, needs_update, status)``.

    ``status`` is ``"ok"`` when PyPI answered, ``"not_published"``
    when the package is not on PyPI yet (404), and ``"unavailable"``
    when PyPI could not be reached (network error or 5xx). In the
    last two cases ``latest`` is ``None``.
    """
    fetcher = fetcher or _pypi_fetcher
    try:
        data = fetcher(PYPI_URL)
    except Exception as exc:  # 404, network error, 5xx: all "no latest"
        return None, False, _classify_pypi_error(exc)
    latest = (data.get("info") or {}).get("version")
    if not latest:
        return None, False, "unavailable"
    return latest, _version_tuple(latest) > _version_tuple(installed_version), "ok"


def check_update(installed_version: str, fetcher=None) -> tuple[str | None, bool]:
    """Return ``(latest, needs_update)``; ``latest is None`` = not on PyPI.

    Kept for callers that only need the version: it collapses the
    ``"unavailable"`` status into ``(None, False)``. New callers
    should use :func:`check_update_status` instead.
    """
    latest, needs_update, _status = check_update_status(installed_version, fetcher)
    return latest, needs_update


def _installed_version() -> str:
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return __version__


def _upgrade_command() -> list[str]:
    if shutil.which("pipx"):
        return ["pipx", "upgrade", PACKAGE_NAME]
    if shutil.which("uv"):
        return ["uv", "tool", "upgrade", PACKAGE_NAME]
    return [sys.executable, "-m", "pip", "install", "--upgrade", PACKAGE_NAME]


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _print_doctor(report: dict, api_url: str, mcp_url: str) -> None:
    print(f"API {api_url}: {'OK' if report['api_ok'] else 'FAILED'}", end="")
    if report["api_writeups"] is not None:
        print(f" ({report['api_writeups']} writeups active)", end="")
    if report["api_error"]:
        print(f" — {report['api_error']}", end="")
    print()
    print(f"MCP {mcp_url}: {'OK' if report['mcp_ok'] else 'FAILED'}", end="")
    if report["mcp_tools"] is not None:
        print(f" ({report['mcp_tools']} tools)", end="")
    print()
    print(f"search_writeups: {'OK' if report['search_ok'] else 'FAILED'}", end="")
    if report["search_error"]:
        print(f" — {report['search_error']}", end="")
    print()
    print("OK" if report["ok"] else "FAILED")


def _manual_instructions(mcp_url: str) -> str:
    return (
        "No supported agent detected (looked for Claude Code, Codex, Cursor).\n"
        "Add the server by hand instead:\n\n"
        "  Claude Code:  claude mcp add --transport http eunoia "
        f"{mcp_url}\n"
        "  Codex:        add to ~/.codex/config.toml:\n"
        "                  [mcp_servers.eunoia]\n"
        f'                  url = "{mcp_url}"\n'
        "  Cursor:       add to ~/.cursor/mcp.json:\n"
        '                  {"mcpServers": {"eunoia": {"url": '
        f'"{mcp_url}"}}}}\n'
        "\nThen restart the agent and ask it to call search_writeups."
    )


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns an exit code (0 = success)."""
    parser = argparse.ArgumentParser(
        prog="eunoia",
        description="Eunoia — wire your agent to the hosted Eunoia MCP server.",
    )
    parser.add_argument("--version", action="store_true", help="print version")
    sub = parser.add_subparsers(dest="command")

    setup_p = sub.add_parser("setup", help="configure detected agents for Eunoia")
    setup_p.add_argument("--home", type=Path, default=Path.home())
    setup_p.add_argument("--api-url", default=HOSTED_API_URL)
    setup_p.add_argument("--mcp-url", default=HOSTED_MCP_URL)
    setup_p.add_argument("--yes", action="store_true", help="apply without asking")
    setup_p.add_argument("--dry-run", action="store_true", help="show the plan only")

    doctor_p = sub.add_parser("doctor", help="check the hosted API and MCP server")
    doctor_p.add_argument("--api-url", default=HOSTED_API_URL)
    doctor_p.add_argument("--mcp-url", default=HOSTED_MCP_URL)

    skills_p = sub.add_parser("skills", help="installable SKILL.md files")
    skills_sub = skills_p.add_subparsers(dest="skills_command")
    install_p = skills_sub.add_parser(
        "install", help="install Eunoia skills into detected agents"
    )
    install_p.add_argument("--home", type=Path, default=Path.home())
    install_p.add_argument("--api-url", default=HOSTED_API_URL)
    install_p.add_argument(
        "--agents",
        default=None,
        help="comma-separated clients to install for: claude-code,codex,cursor",
    )
    install_p.add_argument(
        "--class",
        dest="classes",
        action="append",
        default=None,
        help="install only this vuln class (repeatable)",
    )
    install_p.add_argument("--yes", action="store_true", help="apply without asking")
    install_p.add_argument("--dry-run", action="store_true", help="show the plan only")
    list_p = skills_sub.add_parser("list", help="list installed Eunoia skills")
    list_p.add_argument("--home", type=Path, default=Path.home())

    sub.add_parser("update", help="upgrade eunoia-agents from PyPI")

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)

    if args.version or args.command is None:
        if args.command is None and not args.version:
            parser.print_help()
            return 0
        print(f"eunoia {__version__} ({PACKAGE_NAME})")
        return 0

    if args.command == "doctor":
        report = doctor(args.api_url, args.mcp_url)
        _print_doctor(report, args.api_url, args.mcp_url)
        return 0 if report["ok"] else 1

    if args.command == "skills":
        if args.skills_command == "list":
            found = list_installed_skills(args.home)
            if not found:
                print("No Eunoia skills installed.")
                return 0
            for client_name, names in found.items():
                print(f"{client_name}:")
                for name in names:
                    print(f"  {name}")
            return 0
        if args.skills_command == "install":
            clients = None
            if args.agents:
                wanted = {a.strip() for a in args.agents.split(",") if a.strip()}
                unknown = wanted - {c.name for c in CLIENTS}
                if unknown:
                    print(f"Unknown agent(s): {', '.join(sorted(unknown))}")
                    return 2
                clients = [c for c in CLIENTS if c.name in wanted]
            try:
                skills = fetch_skills(args.api_url, classes=args.classes)
            except Exception as exc:
                print(f"Could not fetch skills from {args.api_url}: {exc}")
                return 1
            installs = plan_skill_installs(args.home, skills, clients=clients)
            if not installs:
                print("Already installed: every skill is up to date.")
                return 0
            targets = sorted({i.client_name for i in installs})
            print("Installing skills for: " + ", ".join(targets))
            print("Planned skill installs:")
            if args.dry_run:
                for install in installs:
                    print(f"  {install.client_name}: {install.action} {install.path}")
                print("Dry run: no changes applied.")
                return 0
            written = apply_skill_installs(installs, yes=args.yes)
            if not written:
                return 1
            print(
                "Done. The skills work over the REST API alone — no MCP "
                "server or local database needed. Restart your agent "
                "if it was already running."
            )
            return 0
        skills_p.print_help()
        return 0

    if args.command == "update":
        installed = _installed_version()
        latest, needs_update, status = check_update_status(installed)
        if status == "not_published":
            print(
                f"{PACKAGE_NAME} is not published on PyPI yet "
                f"(checked {PYPI_URL}).\n"
                f"Until the first PyPI release (blocked on the branch "
                f"being pushed and the package being published), "
                f"update from a checkout instead:\n"
                f"  git pull\n"
                f"  pip install .\n"
                f"Installed version: {installed}"
            )
            return 0
        if status == "unavailable":
            print(
                f"Could not reach PyPI to check for updates "
                f"(checked {PYPI_URL}). Try again later.\n"
                f"Installed version: {installed}"
            )
            return 1
        if not needs_update:
            print(f"eunoia {installed} is up to date (latest {latest}).")
            return 0
        command = _upgrade_command()
        print(f"Upgrading {installed} -> {latest}: {' '.join(command)}")
        result = subprocess.run(command)
        return result.returncode

    # setup
    home: Path = args.home
    clients = detect_clients(home)
    if not clients:
        print(_manual_instructions(args.mcp_url))
        return 1
    print("Detected agents: " + ", ".join(c.display for c in clients))
    changes = planned_changes(home, args.mcp_url)
    if not changes:
        print("Already configured: every detected agent points at Eunoia.")
        return 0
    print("Planned changes:")
    written = apply_changes(changes, yes=args.yes) if not args.dry_run else []
    if args.dry_run:
        for change in changes:
            print(f"  {change.client_name}: {change.action} {change.path}")
        print("Dry run: no changes applied.")
        return 0
    if not written:
        return 1
    print("Done. Restart your agent, then ask it to call search_writeups.")
    return 0
