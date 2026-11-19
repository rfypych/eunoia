"""T4 (Rea-standard): README answers in 1 minute, links are live.

Meta-tests, no database needed. They pin the T4 acceptance criteria:

- The README has, in English: what it is in one sentence, who it is
  for, a quick start, an example agent prompt, a CLI example, a table
  of what can be searched, what it does NOT do, an FAQ, and the MIT
  licence.
- Every relative link in the README resolves to a file in the repo.
- Every absolute URL in the README is pinned, including bare URLs
  inside code blocks (not just markdown links): each one must be an
  endpoint verified live by the implementer on 2026-11-19, a
  /v1/search query on that same host, or the one real canonical
  HackerOne link used as the search example. No other absolute URL
  may appear, so no invented or dead link can sneak in.
- The one-minute sections are pinned by content, not just by a
  keyword: the one-sentence pitch, who it is for, the example agent
  prompt, a CLI example, and the search table must all be present.
- No placeholder strings, and the website/demo is live at the API
  root (T6): every paragraph mentioning it must say it is live,
  never that it is not yet live.
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
# The API root serves the T6 website/demo page: GET / returned 200
# HTML, verified live 2026-11-19 after deploy (eunoia-api restart).
# T9 added two URLs, verified live 2026-11-19: the per-writeup skill
# for the CSRF search example returned 200 markdown, and the SSRF
# writeup used in the skills worked example is in live search results.
VERIFIED_ABSOLUTE_URLS = {
    "https://github.com/rfypych/eunoia",
    "http://129.150.57.82:10004/",
    "http://129.150.57.82:10004/v1/status",
    "http://129.150.57.82:10004/v1/writeups",
    "http://129.150.57.82:10004/llms.txt",
    "http://129.150.57.82:10004/api/v1/openapi.json",
    "http://129.150.57.82:10005/mcp",
    "https://hackerone.com/reports/366638",
    "https://hackerone.com/reports/3882740",
    "http://129.150.57.82:10004/v1/writeups/w_01a1f1a6533177e99904437453565607/skill.md",
}

_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_URL_RE = re.compile(r"https?://[^\s)\"'<>`]+")


def _body() -> str:
    return README.read_text()


def _all_absolute_urls(body: str) -> set[str]:
    urls = set()
    for raw in _URL_RE.findall(body):
        urls.add(raw.rstrip(".,;"))
    return urls


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
    # Pinned by content, not just by a keyword (review M4).
    assert body.startswith(
        "# Eunoia\n\n**Eunoia is an external brain for autonomous pentesting AI agents:"
    ), "README must open with the one-sentence pitch"
    assert "Built for autonomous pentesting agents and the humans who run them." in body, (
        "README must say who it is for"
    )
    assert "Example agent prompt:" in body, "README must have an example agent prompt"
    assert 'curl "http://129.150.57.82:10004/v1/search?q=' in body, (
        "README must have a CLI search example"
    )
    assert "| Ask for | How | Notes |" in body, "README must have the search table"


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


# Bare URLs anywhere in the README (code blocks included) must resolve
# to a verified-live endpoint, a search query on the same API host, or
# the one real canonical HackerOne link used as the search example.
_ALLOWED_BARE_PATHS = {
    ("github.com", "/rfypych/eunoia"),
    ("129.150.57.82:10004", "/"),
    ("129.150.57.82:10004", "/v1/status"),
    ("129.150.57.82:10004", "/v1/search"),
    ("129.150.57.82:10004", "/v1/writeups"),
    ("129.150.57.82:10004", "/llms.txt"),
    ("129.150.57.82:10004", "/api/v1/openapi.json"),
    ("129.150.57.82:10005", "/mcp"),
    ("hackerone.com", "/reports/3882740"),
    ("hackerone.com", "/reports/366638"),
    ("129.150.57.82:10004", "/v1/writeups/w_01a1f1a6533177e99904437453565607/skill.md"),
}


def test_readme_bare_urls_are_verified_live():
    for url in sorted(_all_absolute_urls(_body())):
        parsed = urlparse(url)
        assert (parsed.netloc, parsed.path) in _ALLOWED_BARE_PATHS, (
            f"README contains an absolute URL that was not verified live: {url}"
        )


def test_readme_has_no_placeholders_and_website_is_live():
    body = _body()
    lowered = body.lower()
    assert "placeholder" not in lowered
    assert "dmca@eunoia.example" not in lowered
    assert "example.com" not in lowered
    assert "todo" not in lowered
    # Tightened (review M4, updated T6): every paragraph mentioning
    # the website must say it is live, never "not yet live".
    for paragraph in body.split("\n\n"):
        if "website" not in paragraph.lower():
            continue
        assert "not yet live" not in paragraph.lower(), (
            f"a paragraph says the website is not yet live: {paragraph[:120]!r}"
        )
        assert "live" in paragraph.lower(), (
            f"a paragraph mentions the website without saying it is live: {paragraph[:120]!r}"
        )
