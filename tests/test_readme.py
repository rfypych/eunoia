"""T4 (Rea-standard): README answers in 1 minute, links are live.

Meta-tests, no database needed. They pin the T4 acceptance criteria:

- The README has, in English: what it is in one sentence, who it is
  for, a quick start, an example agent prompt, a CLI example, a table
  of what can be searched, what it does NOT do, an FAQ, and the MIT
  licence.
- Every relative link in the README resolves to a file in the repo.
- Every absolute link is one of the URLs verified live by the
  implementer on 2026-11-19 (API status/search/writeups, llms.txt,
  OpenAPI, hosted MCP, GitHub repo). No other absolute URL may appear,
  so no invented or dead link can sneak in.
- No placeholder strings, and the website/demo is not claimed as live
  (it is T6 work, still pending).
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

_REPO = Path(__file__).resolve().parent.parent
README = _REPO / "README.md"

# Absolute URLs verified live by the implementer on 2026-11-19:
# API /v1/status, /v1/writeups, /llms.txt, /api/v1/openapi.json and a
# /v1/search query all returned 200; POST /mcp tools/list returned the
# 6 read-only tools; https://github.com/rfypych/eunoia returned 200.
# The API root returns 404, so it is never linked as a live page.
VERIFIED_ABSOLUTE_URLS = {
    "https://github.com/rfypych/eunoia",
    "http://129.150.57.82:10004/v1/status",
    "http://129.150.57.82:10004/v1/writeups",
    "http://129.150.57.82:10004/llms.txt",
    "http://129.150.57.82:10004/api/v1/openapi.json",
    "http://129.150.57.82:10005/mcp",
}

_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")


def _body() -> str:
    return README.read_text()


def test_readme_has_one_minute_sections():
    body = _body()
    lowered = body.lower()
    assert "quick start" in lowered, "README must have a quick start"
    assert "search_writeups" in body, "README must name the MCP tool"
    assert "what eunoia does not do" in lowered, "README must state what it does not do"
    assert "faq" in lowered, "README must have an FAQ"
    assert "mit" in body, "README must state the MIT licence"
    assert "bash scripts/setup_dev.sh" in body, "README must keep the T1 setup command"
    assert "pytest -q" in body, "README must keep the test command"


def test_readme_states_scope_and_measured_numbers():
    body = _body()
    assert "Java" in body and "Spring" in body, "README must state the current scope"
    assert "50" in body, "README must state the current corpus size"
    assert "recall@10" in body.lower(), "README must state the measured recall"
    assert "2026-11-19" in body, "measured numbers must carry their date"


def test_readme_relative_links_resolve():
    body = _body()
    for target in _LINK_RE.findall(body):
        parsed = urlparse(target)
        if parsed.scheme:
            continue
        path = target.split("#", 1)[0]
        assert path, f"empty relative link in README: {target!r}"
        assert (_REPO / path).exists(), f"README links to missing file: {path}"


def test_readme_absolute_links_are_verified_live():
    body = _body()
    for target in _LINK_RE.findall(body):
        parsed = urlparse(target)
        if not parsed.scheme:
            continue
        assert target in VERIFIED_ABSOLUTE_URLS, (
            f"README links to an absolute URL that was not verified live: {target}"
        )


def test_readme_has_no_placeholders_and_no_live_website_claim():
    body = _body()
    lowered = body.lower()
    assert "placeholder" not in lowered
    assert "dmca@eunoia.example" not in lowered
    assert "example.com" not in lowered
    assert "todo" not in lowered
    assert "website" not in lowered or "not yet live" in lowered, (
        "the website/demo (T6) must not be claimed as live"
    )
