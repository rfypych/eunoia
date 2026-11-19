"""T11 (Rea-standard): structured documentation.

Pins the T11 acceptance criteria, all as meta-tests (no database):

- A docs index exists and maps the whole guide: install, MCP, CLI,
  API, FAQ, troubleshooting, roadmap, changelog, showcases,
  runbook, transparency, takedown, and the Definition of Done.
- The guide files exist: docs/api.md, docs/cli.md, docs/install.md,
  docs/troubleshooting.md, docs/roadmap.md.
- Every relative link in the README and in every doc resolves to a
  file in the repo; every absolute URL is one verified live.
- No placeholder wording anywhere in the public docs, including the
  literal DMCA placeholder address: the open item is recorded as
  "not yet set", never as a fake address.
- No mention of how the software was built (internal working
  method) anywhere in the public docs.
- The numbers in the README match the live state: 507 writeups,
  recall@10 0.9048, p50 46.89 ms, p95 78.45 ms, all dated
  2026-11-19; the unclassified count is dated, with a pointer to
  the live endpoint, because the live count moves as the poller
  classifies.
- The served llms.txt scope is not Java/Spring-only.
- The install -> first query -> showcase flow is written in order
  in the docs index, so it can be followed without help.
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

_REPO = Path(__file__).resolve().parent.parent

# Public docs: everything a reader can open. Internal measurement
# records under docs/ are included too: they ship in the repo.
_PUBLIC_DOCS = [
    _REPO / "README.md",
    _REPO / "CHANGELOG.md",
    _REPO / "CONTRIBUTING.md",
    _REPO / "SECURITY.md",
    *_REPO.glob("docs/**/*.md"),
]

_GUIDES = {
    "docs/index.md": ("install", "mcp", "cli", "api", "faq",
                      "troubleshooting", "roadmap", "changelog",
                      "showcases", "runbook", "transparency",
                      "takedown", "definition of done"),
    "docs/api.md": ("search", "writeups", "status", "limit", "api key"),
    "docs/cli.md": ("setup", "doctor", "update", "skills"),
    "docs/install.md": ("pip install", "checkout", "pypi"),
    "docs/troubleshooting.md": ("postgres", "pgvector", "test database"),
    "docs/roadmap.md": ("done", "open", "dmca", "pypi", "registry"),
}

_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_URL_RE = re.compile(r"https?://[^\s)\"'<>`]+")


def _text(path: Path) -> str:
    return path.read_text()


def _all_absolute_urls() -> set[str]:
    urls: set[str] = set()
    for path in _PUBLIC_DOCS:
        for raw in _URL_RE.findall(_text(path)):
            urls.add(raw.rstrip(".,;:"))
    return urls


def test_docs_index_exists_and_lists_all_guides():
    index = _REPO / "docs" / "index.md"
    assert index.exists(), "docs/index.md is missing"
    lowered = _text(index).lower()
    for topic in _GUIDES["docs/index.md"]:
        assert topic in lowered, f"docs/index.md does not mention {topic!r}"


def test_guide_files_exist_and_cover_their_topic():
    for rel, topics in _GUIDES.items():
        path = _REPO / rel
        assert path.exists(), f"{rel} is missing"
        lines = _text(path).splitlines()
        assert len(lines) >= 20, f"{rel} is suspiciously short"
        lowered = _text(path).lower()
        for topic in topics:
            assert topic in lowered, f"{rel} does not cover {topic!r}"


def test_docs_flow_install_to_showcase_in_order():
    lowered = _text(_REPO / "docs" / "index.md").lower()
    positions = [lowered.index(word) for word in ("install", "query", "showcase")]
    assert positions == sorted(positions), (
        "docs/index.md must present the flow install -> query -> showcase in order")


def test_all_relative_links_resolve():
    for path in _PUBLIC_DOCS:
        for target in _LINK_RE.findall(_text(path)):
            if urlparse(target).scheme:
                continue
            link_path = target.split("#", 1)[0]
            assert link_path, f"empty relative link in {path}: {target!r}"
            resolved = (path.parent / link_path).resolve()
            assert resolved.exists(), (
                f"{path} links to missing file: {target!r}")


# Absolute URLs verified live on 2026-11-19: the API host endpoints
# (status, writeups, search, llms.txt, OpenAPI, root), the MCP host,
# the GitHub repo, the HackerOne API, canonical HackerOne report
# links, the MCP specification, and the sources cited in the
# stateless-protocol probe record.
_ALLOWED_URL_HOSTS = {
    "129.150.57.82:10004",
    "129.150.57.82:10005",
    "github.com",
    "hackerone.com",
    "api.hackerone.com",
    "modelcontextprotocol.io",
    "www.querynow.com",
    "www.osmondvanhemert.nl",
    "kanerika.com",
    "betterstack.com",
    "agentic-academy.ai",
    "dev.to",
}
_ALLOWED_API_PATHS = {
    "/", "/v1/status", "/v1/writeups", "/v1/search", "/llms.txt",
    "/api/v1/openapi.json", "/mcp", "/v1/vuln-classes",
}


def test_absolute_urls_in_docs_are_verified_live():
    for url in sorted(_all_absolute_urls()):
        parsed = urlparse(url)
        assert parsed.netloc in _ALLOWED_URL_HOSTS, (
            f"docs contain an absolute URL that was not verified live: {url}")
        if parsed.netloc == "129.150.57.82:10004":
            assert parsed.path in _ALLOWED_API_PATHS or parsed.path == "" \
                or parsed.path.startswith(("/v1/writeups/", "/v1/vuln-classes/")), (
                f"docs link to an unverified API path: {url}")
        if parsed.netloc == "129.150.57.82:10005":
            assert parsed.path == "/mcp", (
                f"docs link to an unverified MCP path: {url}")


def test_no_placeholder_in_public_docs():
    for path in _PUBLIC_DOCS:
        lowered = _text(path).lower()
        assert "placeholder" not in lowered, (
            f"{path} still contains 'placeholder'")
        assert "dmca@eunoia.example" not in lowered, (
            f"{path} still contains the placeholder DMCA address")


def test_no_methodology_mentions_in_public_docs():
    banned = [
        re.compile(r"Task \d+"),
        re.compile(r"\bT\d+\b"),
        re.compile(r"subagent", re.IGNORECASE),
        re.compile(r"\bTDD\b"),
        re.compile(r"test-driven", re.IGNORECASE),
        re.compile(r"implementer", re.IGNORECASE),
        re.compile(r"reviewer", re.IGNORECASE),
        re.compile(r"Ruling R\d"),
        re.compile(r"Review Focus"),
        re.compile(r"one task per branch", re.IGNORECASE),
        re.compile(r"task brief", re.IGNORECASE),
        re.compile(r"spec §"),
    ]
    for path in _PUBLIC_DOCS:
        text = _text(path)
        for pattern in banned:
            assert not pattern.search(text), (
                f"{path} mentions internal working method: {pattern.pattern!r}")


def test_readme_numbers_match_live_state():
    body = _text(_REPO / "README.md")
    for needle in ("507", "0.9048", "46.89", "78.45", "2026-11-19"):
        assert needle in body, f"README is missing live number {needle!r}"
    assert "blocked on the branch being pushed" not in body, (
        "README still says the PyPI release is blocked on the branch push")
    assert "50 writeups" not in body.replace(
        "on the 50-writeup corpus", ""), (
        "README still presents 50 writeups as the current corpus")


def test_changelog_records_t11_and_no_stale_push_block():
    text = _text(_REPO / "CHANGELOG.md")
    assert "T11" in text or "structured documentation" in text.lower(), (
        "CHANGELOG does not record the T11 documentation work")
    assert "blocked on the branch being pushed" not in text, (
        "CHANGELOG still says the PyPI release is blocked on the branch push")
    assert "never claims 500 writeups" not in text, (
        "CHANGELOG still describes the website page as not claiming the corpus size")


def test_transparency_states_current_numbers():
    text = _text(_REPO / "docs" / "transparency.md")
    assert "507" in text, "transparency note still states the old 50-writeup corpus"
    assert "0.9048" in text, "transparency note still states the old recall"
    assert "not yet set" in text.lower(), (
        "transparency note must record the DMCA email as not yet set")
    assert "50 HackerOne writeups" not in text, (
        "transparency note still presents 50 writeups as the production corpus")


def test_llms_scope_is_not_java_only():
    text = _text(_REPO / "src" / "eunoia" / "llms.py")
    assert "for Java and Spring targets" not in text, (
        "llms.txt still says the registry is for Java and Spring targets")
    assert "disclosed HackerOne reports" in text, (
        "llms.txt must state the current scope: all disclosed HackerOne reports")
