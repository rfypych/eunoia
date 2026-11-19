"""T9 (Rea-standard): installable skills.

The contract pinned here:

- The registry skill ships as package data (``eunoia.skills_data``)
  and is byte-identical to what :func:`eunoia.skills.get_registry_skill`
  generates, so the file on disk can never drift from the generator.
- Per-class skills are served live by ``GET /v1/vuln-classes/{class}/skill.md``
  (the same aggregate ``get_vuln_class_skill`` builds), 404 for an
  empty class, never a payload: no non-http(s) link, no secret.
- ``eunoia skills install`` writes the registry skill plus one
  per-class skill per real class (never ``unclassified``) into each
  detected agent's skills directory — Claude Code ``~/.claude/skills``,
  Codex ``~/.agents/skills``, Cursor ``~/.cursor/skills`` (paths
  checked against vendor docs 2026-11-19) — shows the plan, asks for
  approval, writes with a backup, and is idempotent.
- Installed skills work without an MCP server: they teach the agent
  to call the REST API. MCP is only an alternative transport for the
  per-writeup skill, never a requirement.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.api.rest import create_app
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.embed import embed_writeup
from eunoia.models import Base, Source, Writeup, WriteupVuln
from eunoia.safety.secrets_scan import scan_secrets
from eunoia.skills import get_registry_skill, get_vuln_class_skill
from eunoia.cli import (
    HOSTED_API_URL,
    fetch_skills,
    list_installed_skills,
    main,
    plan_skill_installs,
)

REPO = Path(__file__).resolve().parent.parent
TEST_DATABASE_URL = "postgresql+psycopg://eunoia@localhost:5432/eunoia_test"
NOW = datetime.now(timezone.utc)


# --- packaged registry skill -----------------------------------------------

def _packaged_registry_skill() -> str:
    return (
        resources.files("eunoia.skills_data")
        / "eunoia-registry"
        / "SKILL.md"
    ).read_text()


def test_packaged_registry_skill_matches_generator():
    assert _packaged_registry_skill() == get_registry_skill()


def test_registry_skill_ships_as_package_data():
    # The base install is stdlib-only and must still carry the
    # registry skill: without this declaration a wheel would omit it
    # and `eunoia skills install` would fail on a clean machine.
    import tomllib

    data = tomllib.loads((REPO / "pyproject.toml").read_text())
    patterns = data["tool"]["setuptools"]["package-data"]["eunoia"]
    assert any("skills_data" in p and p.endswith(".md") for p in patterns)


def test_packaged_registry_skill_frontmatter_and_safety():
    skill = _packaged_registry_skill()
    assert skill.startswith("---\nname: writeup-registry\ndescription: ")
    assert "Lookup #1" in skill and "Lookup #2" in skill
    assert "/v1/search" in skill  # REST-first: usable without an MCP server
    assert scan_secrets(skill) == []
    assert "javascript:" not in skill and "data:text/html" not in skill


# --- REST per-class skill endpoint ------------------------------------------

_VOCAB = ["ssrf", "pdf", "parser", "spring", "boot", "xss", "tomcat"]


class KeywordEncoder:
    def __init__(self):
        self.calls: list[list[str]] = []

    def encode(self, texts):
        self.calls.append(list(texts))
        vectors = []
        for texts_ in texts:
            vec = [0.0] * 384
            for token in re.findall(r"[a-z0-9]+", texts_.lower()):
                vec[hash(token) % 384] += 1.0
            vectors.append(vec)
        return vectors


def _writeup(session, *, url, title, excerpt, author="alice"):
    row = Writeup(
        canonical_url=url, url_hash=url_hash(url), title=title, excerpt=excerpt,
        author_name=author, source_id="hackerone",
        source_type="hackerone_report",
        published_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
        fetched_at=NOW, status="active",
    )
    session.add(row)
    session.flush()
    return row


def _vuln(session, writeup, *, vuln_class, cwe_id):
    row = WriteupVuln(
        writeup_id=writeup.id, vuln_class=vuln_class, cwe_id=cwe_id,
        severity="high", severity_source="hackerone",
    )
    session.add(row)
    return row


@pytest.fixture()
def session():
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.fail(
            "Test database 'eunoia_test' is missing or unreachable. "
            "Create it with: bash scripts/setup_test_db.sh"
        )
    Base.metadata.create_all(engine)
    encoder = KeywordEncoder()
    with Session(engine) as s:
        s.add(Source(
            id="hackerone", name="HackerOne Hacktivity", type="api",
            base_url="https://api.hackerone.com",
            poll_interval_s=900, rate_limit_per_min=600,
            cursor_state={}, last_poll_at=NOW, last_success_at=NOW,
            consecutive_failures=0, enabled=True,
        ))
        w1 = _writeup(
            s, url="https://hackerone.com/reports/689314",
            title="SSRF via PDF parser in Spring Boot",
            excerpt="A PDF parser fetches attacker-controlled URLs.",
        )
        w1.external_id = "hackerone:689314"
        _vuln(s, w1, vuln_class="SSRF", cwe_id="CWE-918")
        w2 = _writeup(
            s, url="https://hackerone.com/reports/700001",
            title="Reflected XSS in Tomcat admin console",
            excerpt="Unsanitized input reflected in the admin page.",
            author="bob",
        )
        w2.external_id = "hackerone:700001"
        _vuln(s, w2, vuln_class="XSS", cwe_id="CWE-79")
        embed_writeup(w1.id, session=s, model=encoder)
        s.commit()
        s.encoder = encoder  # type: ignore[attr-defined]
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def client(session):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    app = create_app(engine=engine, model=session.encoder)
    with TestClient(app) as c:
        yield c


def test_class_skill_endpoint_serves_live_aggregate(client):
    r = client.get("/v1/vuln-classes/SSRF/skill.md")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/markdown")
    assert r.text.startswith("---\nname: ssrf-fundamentals\ndescription: ")
    assert "SSRF via PDF parser in Spring Boot" in r.text
    assert "https://hackerone.com/reports/689314" in r.text
    assert scan_secrets(r.text) == []
    assert "javascript:" not in r.text


def test_class_skill_endpoint_matches_generator(session):
    assert get_vuln_class_skill("SSRF", session=session).startswith(
        "---\nname: ssrf-fundamentals\ndescription: "
    )


def test_class_skill_endpoint_404_for_empty_class(client):
    r = client.get("/v1/vuln-classes/RCE/skill.md")
    assert r.status_code == 404


def test_class_skill_endpoint_case_insensitive(client):
    r = client.get("/v1/vuln-classes/ssrf/skill.md")
    assert r.status_code == 200


# Every class in the live taxonomy (2026-11-19, /v1/vuln-classes)
# must have a specific technique pattern, not the generic fallback:
# a class skill whose pattern section is a placeholder sentence
# teaches nothing about the class.
_LIVE_CLASSES = [
    "Auth Bypass", "Info Disclosure", "IDOR", "XSS", "DoS",
    "Memory Safety", "Path Traversal", "SSRF", "Privilege Escalation",
    "SQLi", "RCE", "Open Redirect", "Injection", "CSRF", "Clickjacking",
    "Deserialization", "Race Condition", "XXE", "Unrestricted File Upload",
    "Request Smuggling",
]


def test_every_live_class_has_a_specific_pattern():
    from eunoia.skills import _class_pattern

    for name in _LIVE_CLASSES:
        pattern = _class_pattern(name)
        assert not pattern.startswith("This writeup documents"), (
            f"{name} falls back to the generic pattern"
        )
        assert "pattern to study" in pattern


def test_csrf_class_skill_teaches_the_csrf_pattern(session):
    w = _writeup(
        session, url="https://hackerone.com/reports/3882740",
        title="All stored Slack and Teams credentials can be deleted via Management Console CSRF",
        excerpt="State-changing request without a token.",
        author="nikhil",
    )
    w.external_id = "hackerone:3882740"
    _vuln(session, w, vuln_class="CSRF", cwe_id="CWE-352")
    session.commit()
    skill = get_vuln_class_skill("CSRF", session=session)
    assert "Cross-Site Request Forgery" in skill
    assert "This writeup documents a CSRF technique" not in skill


# --- CLI install -------------------------------------------------------------

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


_SSRF_SKILL = """---
name: ssrf-fundamentals
description: Fundamentals of SSRF, from the best verified writeups in the registry.
---
# SSRF fundamentals

> **Authorization required:** only test systems you have written authorization to test.

## Technique pattern

Server-Side Request Forgery happens when a server fetches a URL supplied by the user without checking where it points.

## Best verified writeups

- [SSRF via PDF parser](https://hackerone.com/reports/689314)

## References

- CWE-918: https://cwe.mitre.org/data/definitions/918.html

## berlatih dengan aman

Practice this technique only in a lab.
"""

_XSS_SKILL = """---
name: xss-fundamentals
description: Fundamentals of XSS, from the best verified writeups in the registry.
---
# XSS fundamentals

> **Authorization required:** only test systems you have written authorization to test.

## Technique pattern

Cross-Site Scripting happens when user-controlled input is reflected and rendered as code in a browser.
"""


def _stub_opener_factory(seen: list[str]):
    """Fake hosted API: 3 classes (one unclassified), 2 class skills."""
    def opener(request, timeout=10):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        seen.append(url)
        if url.endswith("/v1/vuln-classes"):
            return _FakeResponse(json.dumps({"items": [
                {"vuln_class": "SSRF", "writeup_count": 16},
                {"vuln_class": "XSS", "writeup_count": 47},
                {"vuln_class": "unclassified", "writeup_count": 38},
            ]}).encode())
        if url.endswith("/vuln-classes/SSRF/skill.md"):
            return _FakeResponse(_SSRF_SKILL.encode())
        if url.endswith("/v1/vuln-classes/XSS/skill.md"):
            return _FakeResponse(_XSS_SKILL.encode())
        raise AssertionError(f"unexpected URL {url}")
    return opener


@pytest.fixture(autouse=True)
def _isolated_path(tmp_path, monkeypatch):
    bindir = tmp_path / "emptybin"
    bindir.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(bindir))


def _fake_home(tmp_path: Path) -> Path:
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude.json").write_text("{}")
    (home / ".codex").mkdir(parents=True)  # Codex marker (.codex/config.toml or dir)
    (home / ".agents").mkdir(parents=True)  # Codex skills dir marker
    return home


def test_fetch_skills_includes_registry_and_classes_but_not_unclassified(tmp_path):
    seen: list[str] = []
    skills = fetch_skills(HOSTED_API_URL, opener=_stub_opener_factory(seen))
    names = [s.name for s in skills]
    assert names == ["writeup-registry", "ssrf-fundamentals", "xss-fundamentals"]
    assert not any("unclassified" in url for url in seen)
    assert skills[0].text == get_registry_skill()
    assert skills[1].text == _SSRF_SKILL


def test_fetch_skills_rejects_bad_frontmatter():
    def opener(request, timeout=10):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url.endswith("/v1/vuln-classes"):
            return _FakeResponse(json.dumps({"items": [
                {"vuln_class": "SSRF", "writeup_count": 1},
            ]}).encode())
        return _FakeResponse(b"# no frontmatter at all\n")

    with pytest.raises(ValueError, match="frontmatter"):
        fetch_skills(HOSTED_API_URL, opener=opener)


def test_fetch_skills_rejects_non_http_link():
    def opener(request, timeout=10):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        if url.endswith("/v1/vuln-classes"):
            return _FakeResponse(json.dumps({"items": [
                {"vuln_class": "SSRF", "writeup_count": 1},
            ]}).encode())
        return _FakeResponse(
            _SSRF_SKILL.replace(
                "https://hackerone.com/reports/689314",
                "javascript:alert(1)",
            ).encode()
        )

    with pytest.raises(ValueError, match="javascript:"):
        fetch_skills(HOSTED_API_URL, opener=opener)


def test_skills_install_writes_detected_clients_and_is_idempotent(tmp_path, monkeypatch):
    import eunoia.cli as cli

    home = _fake_home(tmp_path)
    seen: list[str] = []
    monkeypatch.setattr(cli, "_default_opener", _stub_opener_factory(seen))
    assert main(["skills", "install", "--home", str(home), "--yes"]) == 0
    claude = home / ".claude" / "skills" / "writeup-registry" / "SKILL.md"
    codex = home / ".agents" / "skills" / "ssrf-fundamentals" / "SKILL.md"
    assert claude.read_text() == get_registry_skill()
    assert codex.read_text() == _SSRF_SKILL
    assert (home / ".claude" / "skills" / "xss-fundamentals" / "SKILL.md").exists()
    # Second run: already installed, nothing rewritten.
    assert main(["skills", "install", "--home", str(home), "--yes"]) == 0
    assert (home / ".claude" / "skills" / "writeup-registry" / "SKILL.md").read_text() == get_registry_skill()


def test_skills_install_dry_run_writes_nothing(tmp_path, monkeypatch):
    import eunoia.cli as cli

    home = _fake_home(tmp_path)
    monkeypatch.setattr(cli, "_default_opener", _stub_opener_factory([]))
    assert main(["skills", "install", "--home", str(home), "--dry-run"]) == 0
    assert not (home / ".claude" / "skills").exists()


def test_skills_install_prompt_decline_writes_nothing(tmp_path, monkeypatch):
    import eunoia.cli as cli

    home = _fake_home(tmp_path)
    monkeypatch.setattr(cli, "_default_opener", _stub_opener_factory([]))
    monkeypatch.setattr("builtins.input", lambda prompt: "n")
    assert main(["skills", "install", "--home", str(home)]) == 1
    assert not (home / ".claude" / "skills").exists()


def test_skills_install_backs_up_changed_skill(tmp_path, monkeypatch):
    import eunoia.cli as cli

    home = _fake_home(tmp_path)
    monkeypatch.setattr(cli, "_default_opener", _stub_opener_factory([]))
    target = home / ".claude" / "skills" / "ssrf-fundamentals" / "SKILL.md"
    target.parent.mkdir(parents=True)
    target.write_text("old custom version\n")
    assert main(["skills", "install", "--home", str(home), "--yes"]) == 0
    assert target.read_text() == _SSRF_SKILL
    assert (home / ".claude" / "skills" / "ssrf-fundamentals" / "SKILL.md.bak").read_text() == "old custom version\n"


def test_skills_list_shows_installed(tmp_path, monkeypatch, capsys):
    import eunoia.cli as cli

    home = _fake_home(tmp_path)
    monkeypatch.setattr(cli, "_default_opener", _stub_opener_factory([]))
    assert main(["skills", "install", "--home", str(home), "--yes"]) == 0
    assert main(["skills", "list", "--home", str(home)]) == 0
    out = capsys.readouterr().out
    assert "writeup-registry" in out and "ssrf-fundamentals" in out


def test_plan_skill_installs_skips_unclassified_and_uses_client_dirs(tmp_path):
    home = _fake_home(tmp_path)
    from eunoia.cli import SkillFile

    skills = [
        SkillFile("writeup-registry", get_registry_skill()),
        SkillFile("ssrf-fundamentals", _SSRF_SKILL),
    ]
    installs = plan_skill_installs(home, skills)
    dirs = {str(i.path.parent.parent) for i in installs}
    assert str(home / ".claude" / "skills") in dirs
    assert str(home / ".agents" / "skills") in dirs
    assert all(i.action == "create" for i in installs)
    assert list_installed_skills(home) == {}
