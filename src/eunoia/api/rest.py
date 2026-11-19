"""REST v1 (spec §5.5, Task 10).

Endpoints (all under ``/v1``; OpenAPI 3.x at ``/api/v1/openapi.json``):

* ``GET /v1/writeups`` — list + filters + sort + cursor/page pagination
* ``GET /v1/writeups/{id}`` — one writeup, full object
* ``GET /v1/writeups/{id}.md`` — Markdown rendering of the record
* ``GET /v1/writeups/{id}/skill.md`` — SKILL.md (Task 12 owns the
  generator; until then this is an explicit 501, never a stub skill)
* ``GET /v1/search`` — hybrid search (Task 9), mode keyword|semantic|
  hybrid, default hybrid for keyed callers, keyword for anon
* ``GET /v1/programs`` / ``/v1/authors`` / ``/v1/vuln-classes`` — facets
* ``GET /v1/status`` — public, no key (see ``eunoia.api.status``)
* ``GET /llms.txt`` — llms.txt index (Task 12 renders, Task 16 serves)
* ``GET /`` — website / demo page (T6): HTML, search box calls
  ``/v1/search`` live, corpus size comes from ``/v1/status``
* ``POST /v1/submissions`` — review queue; never auto-indexes

Contract notes (binding handoffs from Task 9):

* search ``limit`` is accepted up to 20 but the search engine clamps
  to [1, 10] (Review Focus 4); values above 10 return at most 10
  results. ``limit=0`` clamps to 1, never to 0.
* ``rerank=true`` is a 501, never a 500: cross-encoder rerank is not
  implemented in MVP.
* every response carries ``X-RateLimit-*`` and ``X-Request-Id``; errors
  use the envelope ``{error: {code, message, retry_after, request_id}}``.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, field_validator
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from eunoia.api.auth import verify_api_key
from eunoia.api.rate_limit import RateLimiter
from eunoia.api.status import build_status
from eunoia.config import Settings, get_settings
from eunoia.db import get_engine
from eunoia.llms import render_llms_txt
from eunoia.models import Source, Submission, Writeup, WriteupSource, WriteupVuln
from eunoia.safety.secrets_scan import SecretFoundError
from eunoia.safety.serving import (
    SERVABLE_STATUSES,
    NotServableError,
    ensure_servable,
    servable_filter,
)
from eunoia.search import SearchResult, search
from eunoia.skills import get_skill_text

__all__ = ["ApiError", "create_app"]

_MAX_PER_PAGE = 100
_MAX_SEARCH_LIMIT = 20

_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 1}
_VALID_SORTS = ("published_at", "bounty", "relevance", "trending")
_VALID_STATUSES = ("active", "updated", "retracted", "takedown", "duplicate_of")


class ApiError(Exception):
    """An error that maps directly onto the error envelope."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        retry_after: int | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retry_after = retry_after


def _envelope(code: str, message: str, request_id: str,
              retry_after: int | None = None) -> dict:
    return {"error": {
        "code": code, "message": message,
        "retry_after": retry_after, "request_id": request_id,
    }}


def _rate_headers(result) -> dict:
    return {
        "X-RateLimit-Limit": str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset": str(result.reset),
    }


class _RateLimitMiddleware(BaseHTTPMiddleware):
    """request_id + auth resolution + rate limiting, on every request.

    Identity is the API-key hash prefix for keyed callers, else the
    client IP. A bad key is a 401 before any quota is consumed.
    """

    async def dispatch(self, request: Request, call_next):
        request_id = uuid.uuid4().hex
        request.state.request_id = request_id
        limiter: RateLimiter = request.app.state.rate_limiter
        engine = request.app.state.engine

        tier = "anon"
        identity = f"anon:{request.client.host if request.client else 'unknown'}"
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            plaintext = auth[len("Bearer "):].strip()
            with Session(engine) as session:
                row = verify_api_key(session, plaintext)
                if row is None:
                    headers = {
                        "X-Request-Id": request_id,
                        "X-RateLimit-Limit": "60",
                        "X-RateLimit-Remaining": "60",
                        "X-RateLimit-Reset": str((int(time.time()) // 60 + 1) * 60),
                    }
                    return JSONResponse(
                        status_code=401,
                        content=_envelope(
                            "UNAUTHORIZED",
                            "API key is invalid or revoked.",
                            request_id,
                        ),
                        headers=headers,
                    )
                tier = row.tier or "free"
                identity = f"key:{row.key_hash[:12]}"
                session.commit()

        result = limiter.check(identity, tier)
        request.state.tier = tier
        request.state.identity = identity
        request.state.rate_limit = result
        if not result.allowed:
            headers = {
                "X-Request-Id": request_id,
                **_rate_headers(result),
                "Retry-After": str(result.retry_after or 60),
            }
            return JSONResponse(
                status_code=429,
                content=_envelope(
                    "RATE_LIMITED",
                    f"Rate limit exceeded for the {tier} tier.",
                    request_id,
                    retry_after=result.retry_after,
                ),
                headers=headers,
            )

        response = await call_next(request)
        response.headers["X-Request-Id"] = request_id
        response.headers.update(_rate_headers(result))
        return response


# ---------------------------------------------------------------------------
# Serialization
# ---------------------------------------------------------------------------


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _vuln_aggregate(vulns: list[WriteupVuln]) -> dict:
    """Aggregate vuln rows into the spec §5.5 ``vulnerability`` object."""
    classes: list[str] = []
    cwe_ids: list[str] = []
    cve_ids: list[str] = []
    for row in vulns:
        for target, value in (
            (classes, row.vuln_class),
            (cwe_ids, row.cwe_id),
            (cve_ids, row.cve_id),
        ):
            if value and value not in target:
                target.append(value)
    severity = None
    severity_source = None
    cvss_score = None
    cvss_vector = None
    best_rank = 0
    for row in vulns:
        rank = _SEVERITY_RANK.get((row.severity or "").lower(), 0)
        if rank > best_rank:
            best_rank = rank
            severity = row.severity
            severity_source = row.severity_source
        if row.cvss_score is not None and (
            cvss_score is None or float(row.cvss_score) > float(cvss_score)
        ):
            cvss_score = float(row.cvss_score)
            cvss_vector = row.cvss_vector
    return {
        "classes": classes,
        "cwe_ids": cwe_ids,
        "cve_ids": cve_ids,
        "severity": severity,
        "severity_source": severity_source,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
    }


def _bounty(vulns: list[WriteupVuln]) -> dict:
    """Bounty from the largest award; ``verified`` is only true when the
    number came from a platform API/record (stored that way by Task 5)."""
    best = None
    for row in vulns:
        if row.bounty_amount is not None and (
            best is None or float(row.bounty_amount) > float(best.bounty_amount)
        ):
            best = row
    if best is None:
        return {"amount": None, "currency": None,
                "verified": False, "verified_against": None}
    return {
        "amount": float(best.bounty_amount),
        "currency": best.bounty_currency,
        "verified": bool(best.bounty_verified),
        "verified_against": best.verified_against,
    }


def _program(vulns: list[WriteupVuln], writeup: Writeup) -> dict | None:
    for row in vulns:
        if row.program:
            return {
                "name": row.program,
                "slug": row.program_slug,
                "platform": writeup.source_id,
            }
    return None


def _related_ids(session: Session, writeup: Writeup,
                 vulns: list[WriteupVuln]) -> list[str]:
    """Up to 5 other servable writeups sharing a CWE or vuln class."""
    cwes = {row.cwe_id for row in vulns if row.cwe_id}
    classes = {row.vuln_class for row in vulns if row.vuln_class}
    if not cwes and not classes:
        return []
    conditions = []
    if cwes:
        conditions.append(WriteupVuln.cwe_id.in_(cwes))
    if classes:
        conditions.append(WriteupVuln.vuln_class.in_(classes))
    rows = (
        session.execute(
            select(WriteupVuln.writeup_id)
            .where(or_(*conditions))
            .where(WriteupVuln.writeup_id != writeup.id)
            .join(Writeup, Writeup.id == WriteupVuln.writeup_id)
            .where(*servable_filter())
            .order_by(Writeup.disclosed_at.desc().nulls_last())
            .limit(5)
        )
        .scalars()
        .all()
    )
    seen: list[str] = []
    for wid in rows:
        api_id = f"w_{wid.hex}"
        if api_id not in seen:
            seen.append(api_id)
    return seen


def _writeup_dict(session: Session, writeup: Writeup) -> dict:
    vulns = (
        session.execute(
            select(WriteupVuln)
            .where(WriteupVuln.writeup_id == writeup.id)
            .order_by(WriteupVuln.id)
        )
        .scalars()
        .all()
    )
    source = (
        session.get(Source, writeup.source_id) if writeup.source_id else None
    )
    source_urls = (
        session.execute(
            select(WriteupSource)
            .where(WriteupSource.writeup_id == writeup.id)
            .order_by(WriteupSource.first_seen_at)
        )
        .scalars()
        .all()
    )
    api_id = writeup.api_id
    return {
        "id": api_id,
        "canonical_url": writeup.canonical_url,
        "title": writeup.title,
        "excerpt": writeup.excerpt,
        "author": {"name": writeup.author_name, "url": writeup.author_url},
        "source": {
            "id": writeup.source_id,
            "type": writeup.source_type,
            "name": source.name if source else None,
        },
        "source_urls": [
            {"source": row.source_id, "url": row.source_url}
            for row in source_urls
        ],
        # published_at is the source date, never the fetch date.
        "published_at": _iso(writeup.published_at),
        "disclosed_at": _iso(writeup.disclosed_at),
        "fetched_at": _iso(writeup.fetched_at),
        "vulnerability": _vuln_aggregate(vulns),
        "program": _program(vulns, writeup),
        "bounty": _bounty(vulns),
        "status": writeup.status,
        "license_note": writeup.license_note,
        "skill_url": f"/v1/writeups/{api_id}/skill.md",
        "markdown_url": f"/v1/writeups/{api_id}.md",
        "related_writeup_ids": _related_ids(session, writeup, vulns),
    }


def _parse_api_id(raw: str) -> uuid.UUID:
    """``w_<hex>`` → UUID; anything else is an unknown id (404)."""
    try:
        if raw.startswith("w_"):
            return uuid.UUID(hex=raw[2:])
    except (ValueError, AttributeError):
        pass
    raise ApiError(404, "NOT_FOUND", f"No writeup with id {raw!r}.")


def _get_writeup_or_404(session: Session, raw: str) -> Writeup:
    writeup = session.get(Writeup, _parse_api_id(raw))
    if writeup is None:
        raise ApiError(404, "NOT_FOUND", f"No writeup with id {raw!r}.")
    return writeup


# ---------------------------------------------------------------------------
# List endpoint: filters, sorts, keyset cursor pagination
# ---------------------------------------------------------------------------


def _like_pattern(text: str) -> str:
    """Escape LIKE wildcards in user input."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _list_filters(
    q: str | None,
    vuln_class: str | None,
    cwe: str | None,
    cve: str | None,
    program: str | None,
    author: str | None,
    severity: str | None,
    source: str | None,
    bounty_verified: bool | None,
    published_after: datetime | None,
    published_before: datetime | None,
    tech: str | None,
    status: str,
):
    """WHERE clauses; vuln fields use EXISTS so one writeup stays one row.

    A record that failed the quality gate (``quality_passed is False``)
    is never listed, whatever ``status`` filter the caller asks for
    (Task 16 shared serving gate). The public list endpoint serves
    only servable statuses; a caller-supplied ``status`` outside the
    servable set is rejected by the endpoint (400) before this
    function runs (final review C1) — there is no review-queue query
    surface on the public API. The detail endpoints refuse gated rows
    with 410 Gone.
    """
    filters = [Writeup.status == status,
               Writeup.quality_passed.is_not(False)]
    if q:
        pattern = _like_pattern(q)
        filters.append(
            or_(
                Writeup.title.ilike(pattern, escape="\\"),
                Writeup.excerpt.ilike(pattern, escape="\\"),
            )
        )
    if author:
        filters.append(Writeup.author_name.ilike(_like_pattern(author), escape="\\"))
    if source:
        filters.append(Writeup.source_id == source)
    if published_after is not None:
        filters.append(
            func.coalesce(Writeup.published_at, Writeup.disclosed_at)
            >= published_after
        )
    if published_before is not None:
        filters.append(
            func.coalesce(Writeup.published_at, Writeup.disclosed_at)
            <= published_before
        )
    if tech:
        pattern = _like_pattern(tech)
        filters.append(
            or_(
                Writeup.title.ilike(pattern, escape="\\"),
                Writeup.excerpt.ilike(pattern, escape="\\"),
                select(WriteupVuln.id)
                .where(WriteupVuln.writeup_id == Writeup.id)
                .where(WriteupVuln.program.ilike(pattern, escape="\\"))
                .exists(),
            )
        )

    def _vuln_exists(*conditions) -> Any:
        return (
            select(WriteupVuln.id)
            .where(WriteupVuln.writeup_id == Writeup.id)
            .where(*conditions)
            .exists()
        )

    if vuln_class:
        filters.append(_vuln_exists(WriteupVuln.vuln_class == vuln_class))
    if cwe:
        filters.append(_vuln_exists(WriteupVuln.cwe_id == cwe.upper()))
    if cve:
        filters.append(_vuln_exists(WriteupVuln.cve_id == cve.upper()))
    if program:
        filters.append(
            _vuln_exists(WriteupVuln.program.ilike(_like_pattern(program), escape="\\"))
        )
    if severity:
        filters.append(_vuln_exists(WriteupVuln.severity == severity.lower()))
    if bounty_verified is not None:
        filters.append(
            _vuln_exists(WriteupVuln.bounty_verified.is_(bounty_verified))
        )
    return filters


def _sort_keys(sort: str, q: str | None):
    """Sort-key expressions + their cursor value kinds (``dt``/``num``).

    All sorts are DESC with NULLS LAST and the writeup id as tiebreak,
    so the keyset cursor is a plain lexicographic comparison.
    """
    published = func.coalesce(Writeup.disclosed_at, Writeup.published_at)
    max_bounty = (
        select(func.max(WriteupVuln.bounty_amount))
        .where(WriteupVuln.writeup_id == Writeup.id)
        .scalar_subquery()
    )
    if sort == "bounty":
        return [(max_bounty, "num")]
    if sort == "relevance" and q:
        pattern = _like_pattern(q)
        score = (
            case((Writeup.title.ilike(pattern, escape="\\"), 2), else_=0)
            + case((Writeup.excerpt.ilike(pattern, escape="\\"), 1), else_=0)
        )
        return [(score, "num"), (published, "dt")]
    if sort == "trending":
        return [(published, "dt"), (max_bounty, "num")]
    return [(published, "dt")]


def _encode_cursor(values: list, writeup_id: uuid.UUID) -> str:
    def _encode_value(value):
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, Decimal):
            return float(value)
        return value

    raw = json.dumps({
        "v": [_encode_value(value) for value in values],
        "id": writeup_id.hex,
    }).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _decode_cursor(cursor: str, kinds: list[str]) -> tuple[list, uuid.UUID]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode())
        raw_values = data["v"]
        if not isinstance(raw_values, list) or len(raw_values) != len(kinds):
            # Final review I6: a short "v" array used to zip silently
            # and raise IndexError in _keyset_condition (500). A
            # malformed cursor is a client error, never a 500.
            raise ApiError(
                400, "VALIDATION_ERROR",
                "Invalid cursor: value array does not match the sort.")
        values = []
        for kind, value in zip(kinds, raw_values):
            if value is None:
                values.append(None)
            elif kind == "dt":
                values.append(datetime.fromisoformat(value))
            else:
                values.append(float(value))
        return values, uuid.UUID(hex=data["id"])
    except ApiError:
        raise
    except (ValueError, KeyError, TypeError, AttributeError):
        raise ApiError(400, "VALIDATION_ERROR", "Invalid cursor.")


def _keyset_condition(inner, keys, values, cursor_id: uuid.UUID):
    """Rows strictly after the cursor under DESC NULLS LAST ordering.

    NULL is the smallest value (it sorts last), so "after" a non-null
    value includes every NULL row, and "after" a NULL value only
    includes NULL rows with a smaller id.
    """
    cols = [inner.c[f"k{i}"] for i in range(len(keys))]
    clauses = []
    for i, (col, value) in enumerate(zip(cols, values)):
        prefix = [
            cols[j].isnot_distinct_from(values[j]) for j in range(i)
        ]
        if value is None:
            less = func.false()
        else:
            less = or_(col < value, and_(col.is_(None)))
        clauses.append(and_(*prefix, less) if prefix else less)
    all_equal = and_(*[
        cols[j].isnot_distinct_from(values[j]) for j in range(len(cols))
    ])
    clauses.append(and_(all_equal, inner.c.id < cursor_id))
    return or_(*clauses)


# ---------------------------------------------------------------------------
# Request bodies
# ---------------------------------------------------------------------------


class SubmissionIn(BaseModel):
    """POST /v1/submissions body: ``{url, notes?}`` only — no uploads."""

    model_config = ConfigDict(extra="forbid")

    url: str
    notes: str | None = None

    @field_validator("url")
    @classmethod
    def _must_be_http_url(cls, value: str) -> str:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("url must be an http(s) URL")
        return value


# ---------------------------------------------------------------------------
# Website / demo page (T6)
# ---------------------------------------------------------------------------

_WEBSITE_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Eunoia — external brain for pentesting agents</title>
<style>
body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2em auto; padding: 0 1em; line-height: 1.5; }
input { width: 70%; padding: 0.5em; font-size: 1em; }
button { padding: 0.5em 1em; font-size: 1em; }
.example { margin: 0.3em 0.3em 0.3em 0; }
li { margin-bottom: 1em; }
.meta { color: #555; margin: 0.2em 0; }
</style>
</head>
<body>
<h1>Eunoia</h1>
<p><strong>Eunoia is an external brain for autonomous pentesting AI agents:
stack in, attack plan out.</strong></p>
<p id="status">Loading corpus status&hellip;</p>
<form id="search-form">
<label for="search">Search real public writeups:</label><br>
<input id="search" name="q" type="search" value="CSRF" autocomplete="off">
<button type="submit">Search</button>
</form>
<p>
<button class="example" type="button" data-q="CSRF">CSRF</button>
<button class="example" type="button" data-q="XSS">XSS</button>
<button class="example" type="button" data-q="IDOR">IDOR</button>
<button class="example" type="button" data-q="SSRF">SSRF</button>
</p>
<div id="results"></div>
<h2>Scope and install</h2>
<p>Corpus: real public HackerOne writeups, all disclosed reports
(not Java/Spring-only). Growing the corpus is planned work; the
live count above comes from the API status endpoint.</p>
<p>Install: from a checkout, <code>pip install .</code>, then
<code>eunoia setup</code>. The <code>eunoia-agents</code> package is
not on PyPI yet.</p>
<p>Eunoia stores metadata and links, not full text. It does not test
anything live. Every hypothesis still needs explicit in-scope
permission before any testing.</p>
<h2>Links</h2>
<ul>
<li><a href="/v1/status">API status</a></li>
<li><a href="/v1/writeups">Writeups</a></li>
<li><a href="/llms.txt">llms.txt</a></li>
<li><a href="/api/v1/openapi.json">API docs (OpenAPI)</a></li>
<li><a href="http://129.150.57.82:10005/mcp">MCP endpoint</a></li>
<li><a href="https://github.com/rfypych/eunoia">GitHub</a></li>
</ul>
<script>
async function runSearch(q) {
  var box = document.getElementById("results");
  box.textContent = "Searching\\u2026";
  var res = await fetch("/v1/search?q=" + encodeURIComponent(q) + "&limit=5");
  var data = await res.json();
  box.textContent = "";
  if (!data.results || data.results.length === 0) {
    box.textContent = "No results for " + q + ".";
    return;
  }
  var list = document.createElement("ul");
  for (var i = 0; i < data.results.length; i++) {
    var r = data.results[i];
    var li = document.createElement("li");
    var a = document.createElement("a");
    a.href = r.canonical_url;
    a.textContent = r.title;
    a.target = "_blank";
    a.rel = "noopener";
    var meta = document.createElement("p");
    meta.className = "meta";
    var parts = [];
    if (r.severity) { parts.push(r.severity); }
    if (r.cwe_ids && r.cwe_ids.length) { parts.push(r.cwe_ids.join(", ")); }
    if (r.score !== undefined && r.score !== null) { parts.push("score " + r.score); }
    meta.textContent = parts.join(" \\u00b7 ");
    li.appendChild(a);
    li.appendChild(meta);
    list.appendChild(li);
  }
  box.appendChild(list);
}
fetch("/v1/status").then(function (res) { return res.json(); }).then(function (s) {
  var el = document.getElementById("status");
  var source = (s.sources && s.sources.length) ? s.sources[0].status : "unknown";
  el.textContent = s.writeups_active + " writeups active \\u00b7 HackerOne: " + source;
}).catch(function () {});
document.getElementById("search-form").addEventListener("submit", function (e) {
  e.preventDefault();
  runSearch(document.getElementById("search").value);
});
var buttons = document.querySelectorAll("button.example");
for (var i = 0; i < buttons.length; i++) {
  buttons[i].addEventListener("click", function (e) {
    var q = e.currentTarget.getAttribute("data-q");
    document.getElementById("search").value = q;
    runSearch(q);
  });
}
runSearch("CSRF");
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------


def create_app(
    *,
    settings: Settings | None = None,
    engine=None,
    model=None,
    rate_limiter: RateLimiter | None = None,
) -> FastAPI:
    """Build the v1 app. ``engine``/``model``/``rate_limiter`` are
    injectable so tests can point the app at the test DB and a stub
    encoder with a fresh limiter; production uses the real ones."""
    settings = settings or get_settings()
    engine = engine or get_engine(settings)
    app = FastAPI(
        title="Eunoia",
        description=(
            "External brain for autonomous pentesting AI agents. "
            "Stack in, attack plan out. Public, authorized bug-bounty "
            "writeups: metadata + link, not full text."
        ),
        version="0.1.0",
        openapi_url="/api/v1/openapi.json",
    )
    app.state.engine = engine
    app.state.model = model
    app.state.rate_limiter = rate_limiter or RateLimiter()
    app.add_middleware(_RateLimitMiddleware)

    def _session(request: Request):
        session = Session(request.app.state.engine)
        try:
            yield session
        finally:
            session.close()

    # -- error handling: every error uses the envelope ----------------------
    @app.exception_handler(ApiError)
    async def _api_error(request: Request, exc: ApiError):
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(
                exc.code, exc.message,
                getattr(request.state, "request_id", uuid.uuid4().hex),
                retry_after=exc.retry_after,
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        code = {
            404: "NOT_FOUND", 401: "UNAUTHORIZED", 403: "FORBIDDEN",
        }.get(exc.status_code, "ERROR")
        return JSONResponse(
            status_code=exc.status_code,
            content=_envelope(
                code, exc.detail,
                getattr(request.state, "request_id", uuid.uuid4().hex),
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=400,
            content=_envelope(
                "VALIDATION_ERROR",
                "; ".join(
                    f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}"
                    for err in exc.errors()
                ),
                getattr(request.state, "request_id", uuid.uuid4().hex),
            ),
        )

    @app.exception_handler(Exception)
    async def _unexpected_error(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content=_envelope(
                "INTERNAL_ERROR", "Internal error.",
                getattr(request.state, "request_id", uuid.uuid4().hex),
            ),
        )

    # -- endpoints ----------------------------------------------------------

    @app.get("/v1/writeups")
    def list_writeups(
        request: Request,
        session: Session = Depends(_session),
        q: str | None = None,
        vuln_class: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        program: str | None = None,
        author: str | None = None,
        severity: str | None = None,
        source: str | None = None,
        bounty_verified: bool | None = None,
        published_after: datetime | None = None,
        published_before: datetime | None = None,
        tech: str | None = None,
        sort: Literal["published_at", "bounty", "relevance", "trending"] = "published_at",
        status: str = "active",
        page: int = 1,
        per_page: int = 20,
        cursor: str | None = None,
    ):
        """List writeups (default ``status=active``). Cursor pagination
        is preferred; ``page``/``per_page`` is the offset fallback."""
        if status not in _VALID_STATUSES:
            raise ApiError(
                400, "VALIDATION_ERROR", f"Unknown status: {status!r}.")
        if status not in SERVABLE_STATUSES:
            # Final review C1: the public list endpoint serves only
            # servable rows; retracted / takedown / duplicate rows are
            # not listed with their full excerpts to anonymous callers.
            # There is no review-queue query surface on the public API.
            raise ApiError(
                400, "VALIDATION_ERROR",
                f"Status {status!r} is not served by the public list "
                "endpoint (servable: active, updated).")
        if sort not in _VALID_SORTS:
            raise ApiError(
                400, "VALIDATION_ERROR", f"Unknown sort: {sort!r}.")
        per_page = max(1, min(int(per_page), _MAX_PER_PAGE))
        page = max(1, int(page))
        keys = _sort_keys(sort, q)
        kinds = [kind for _, kind in keys]
        filters = _list_filters(
            q, vuln_class, cwe, cve, program, author, severity, source,
            bounty_verified, published_after, published_before, tech, status,
        )
        inner = (
            select(
                Writeup.id,
                *[expr.label(f"k{i}") for i, (expr, _) in enumerate(keys)],
            )
            .where(*filters)
            .subquery()
        )
        total = session.execute(
            select(func.count()).select_from(inner)
        ).scalar() or 0
        stmt = select(inner)
        if cursor is not None:
            values, cursor_id = _decode_cursor(cursor, kinds)
            stmt = stmt.where(_keyset_condition(inner, keys, values, cursor_id))
        else:
            stmt = stmt.offset((page - 1) * per_page)
        order = [
            inner.c[f"k{i}"].desc().nulls_last()
            for i in range(len(keys))
        ] + [inner.c.id.desc()]
        # Fetch one extra row: a full page alone cannot tell whether a
        # next page exists, and a trailing cursor to an empty page is a lie.
        rows = session.execute(
            stmt.order_by(*order).limit(per_page + 1)).all()
        has_more = len(rows) > per_page
        rows = rows[:per_page]
        ids = [row[0] for row in rows]
        writeups = {
            w.id: w
            for w in session.execute(
                select(Writeup).where(Writeup.id.in_(ids))
            ).scalars().all()
        } if ids else {}
        items = [_writeup_dict(session, writeups[wid]) for wid in ids]
        next_cursor = None
        if has_more and rows:
            last = rows[-1]
            next_cursor = _encode_cursor(
                [last[1 + i] for i in range(len(keys))], last[0])
        return {"items": items, "total": int(total),
                "cursor": next_cursor, "per_page": per_page}

    @app.get("/v1/writeups/{raw_id}.md")
    def writeup_markdown(raw_id: str, session: Session = Depends(_session)):
        """Markdown rendering of one writeup record (metadata + links,
        never full text — the registry does not store it)."""
        writeup = _get_writeup_or_404(session, raw_id)
        try:
            ensure_servable(writeup)
        except NotServableError as exc:
            raise ApiError(410, "GONE", str(exc))
        body = _writeup_dict(session, writeup)
        vuln = body["vulnerability"]
        lines = [
            f"# {writeup.title}",
            "",
            f"Canonical URL: {writeup.canonical_url}",
            f"Author: {body['author']['name'] or 'unknown'}",
            f"Status: {writeup.status}",
            f"Published: {body['published_at'] or 'unknown'}",
            f"Disclosed: {body['disclosed_at'] or 'unknown'}",
            "",
            "## Vulnerability",
            "",
            f"Classes: {', '.join(vuln['classes']) or 'unclassified'}",
            f"CWE: {', '.join(vuln['cwe_ids']) or 'unknown'}",
            f"CVE: {', '.join(vuln['cve_ids']) or 'unknown'}",
            f"Severity: {vuln['severity'] or 'unknown'}",
            "",
            "## Summary",
            "",
            writeup.excerpt or "No excerpt.",
            "",
            "## References",
            "",
        ]
        for source_url in body["source_urls"]:
            lines.append(f"- {source_url['url']}")
        if writeup.license_note:
            lines.append("")
            lines.append(writeup.license_note)
        return PlainTextResponse(
            "\n".join(lines) + "\n", media_type="text/markdown")

    @app.get("/v1/writeups/{raw_id}/skill.md")
    def writeup_skill(raw_id: str, session: Session = Depends(_session)):
        """Per-writeup SKILL.md (Task 12: ``get_skill_text``).

        A retracted or taken-down writeup is 410 Gone, never a skill
        and never a 500 (Ruling R10). A secret-scan refusal is a
        distinct 503 SECRET_FOUND, never 410: a safety refusal is
        not a takedown.
        """
        writeup = _get_writeup_or_404(session, raw_id)
        try:
            skill = get_skill_text(writeup.api_id, session=session)
        except SecretFoundError as exc:
            raise ApiError(503, "SECRET_FOUND", str(exc))
        except NotServableError as exc:
            raise ApiError(410, "GONE", str(exc))
        return PlainTextResponse(skill, media_type="text/markdown")

    @app.get("/v1/writeups/{raw_id}")
    def get_writeup(raw_id: str, session: Session = Depends(_session)):
        writeup = _get_writeup_or_404(session, raw_id)
        try:
            ensure_servable(writeup)
        except NotServableError as exc:
            raise ApiError(410, "GONE", str(exc))
        return _writeup_dict(session, writeup)

    @app.get("/v1/search")
    def search_endpoint(
        request: Request,
        session: Session = Depends(_session),
        q: str | None = None,
        mode: Literal["keyword", "semantic", "hybrid"] | None = None,
        tech: str | None = None,
        vuln_class: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        program: str | None = None,
        severity: str | None = None,
        bounty_verified: bool | None = None,
        limit: int = 5,
        rerank: bool = False,
        lookup: Literal["pre_test", "mid_test"] = "pre_test",
    ):
        """Hybrid search. Anon callers get keyword mode only; a keyed
        caller defaults to hybrid. ``limit`` is accepted up to 20 but
        the search engine clamps to [1, 10] (Review Focus 4).
        ``lookup`` selects the ranking: ``pre_test`` (plan a test from
        the target stack) or ``mid_test`` (adapt mid-test on a
        candidate / strange response — technique similarity weighs
        in; final review I1)."""
        tier = getattr(request.state, "tier", "anon")
        effective_mode = mode or ("hybrid" if tier != "anon" else "keyword")
        if tier == "anon" and effective_mode != "keyword":
            raise ApiError(
                403, "MODE_REQUIRES_KEY",
                f"Mode {effective_mode!r} requires an API key; "
                "anonymous callers may only use keyword search.",
            )
        if rerank:
            raise ApiError(
                501, "NOT_IMPLEMENTED",
                "Cross-encoder rerank is not implemented in MVP.",
            )
        limit = max(1, min(int(limit), _MAX_SEARCH_LIMIT))
        query: dict[str, Any] = {
            "tech": tuple(
                part.strip().lower() for part in (tech or "").split(",")
                if part.strip()
            ),
            "vuln_class": vuln_class,
            "cwe": cwe,
            "cve": cve,
            "evidence_pattern": q,
            "mode": lookup,
        }
        try:
            results = search(
                query, limit=limit, session=session,
                model=request.app.state.model, retrieval=effective_mode,
            )
        except NotImplementedError as exc:
            raise ApiError(501, "NOT_IMPLEMENTED", str(exc))
        items = []
        if results:
            ids = [
                uuid.UUID(hex=result.writeup_id[2:])
                for result in results
            ]
            writeups = {
                w.id: w
                for w in session.execute(
                    select(Writeup).where(Writeup.id.in_(ids))
                ).scalars().all()
            }
            for result in results:
                writeup = writeups.get(uuid.UUID(hex=result.writeup_id[2:]))
                if writeup is None:
                    continue
                vulns = (
                    session.execute(
                        select(WriteupVuln)
                        .where(WriteupVuln.writeup_id == writeup.id)
                    )
                    .scalars()
                    .all()
                )
                # Filters search() cannot express (program / severity /
                # bounty_verified) are applied after ranking.
                if program and not any(
                    row.program
                    and program.lower() in row.program.lower()
                    for row in vulns
                ):
                    continue
                if severity and not any(
                    (row.severity or "").lower() == severity.lower()
                    for row in vulns
                ):
                    continue
                if bounty_verified is not None and not any(
                    bool(row.bounty_verified) is bounty_verified
                    for row in vulns
                ):
                    continue
                items.append({
                    "writeup_id": result.writeup_id,
                    "title": result.title,
                    "excerpt": writeup.excerpt,
                    "canonical_url": writeup.canonical_url,
                    "severity": _vuln_aggregate(vulns)["severity"],
                    "bounty": _bounty(vulns),
                    "cwe_ids": _vuln_aggregate(vulns)["cwe_ids"],
                    "cve_ids": _vuln_aggregate(vulns)["cve_ids"],
                    "tech": list(query["tech"]),
                    "score": result.score,
                    "score_breakdown": result.score_breakdown,
                    "match_reason": result.match_reason,
                    "verified": result.verified,
                    "verified_label": result.verified_label,
                    "fetched_at": _iso(result.fetched_at),
                    "indexed_at": _iso(result.indexed_at),
                    "freshness": result.freshness,
                    "flags": result.flags,
                })
        status = build_status(session)
        return {
            "results": items,
            "total": len(items),
            "mode": effective_mode,
            "lookup": lookup,
            "limit": min(limit, 10),
            "freshness": {
                row["id"]: {
                    "last_poll_at": row["last_poll_at"],
                    "lag_seconds": row["lag_seconds"],
                }
                for row in status["sources"]
            },
        }

    @app.get("/v1/programs")
    def list_programs(session: Session = Depends(_session)):
        """Normalized programs (facets, so agents never guess strings)."""
        rows = (
            session.execute(
                select(
                    WriteupVuln.program,
                    WriteupVuln.program_slug,
                    func.count(func.distinct(WriteupVuln.writeup_id)),
                )
                .join(Writeup, Writeup.id == WriteupVuln.writeup_id)
                .where(*servable_filter())
                .where(WriteupVuln.program.is_not(None))
                .group_by(WriteupVuln.program, WriteupVuln.program_slug)
                .order_by(func.count(func.distinct(WriteupVuln.writeup_id)).desc())
            )
            .all()
        )
        return {"items": [
            {"name": name, "slug": slug, "writeup_count": int(count)}
            for name, slug, count in rows
        ]}

    @app.get("/v1/authors")
    def list_authors(session: Session = Depends(_session)):
        rows = (
            session.execute(
                select(
                    Writeup.author_name,
                    Writeup.author_url,
                    func.count(),
                )
                .where(*servable_filter())
                .where(Writeup.author_name.is_not(None))
                .group_by(Writeup.author_name, Writeup.author_url)
                .order_by(func.count().desc())
            )
            .all()
        )
        return {"items": [
            {"name": name, "url": url, "writeup_count": int(count)}
            for name, url, count in rows
        ]}

    @app.get("/v1/vuln-classes")
    def list_vuln_classes(session: Session = Depends(_session)):
        """Vuln-class taxonomy (only classes with real MVP data)."""
        rows = (
            session.execute(
                select(
                    WriteupVuln.vuln_class,
                    func.count(func.distinct(WriteupVuln.writeup_id)),
                )
                .join(Writeup, Writeup.id == WriteupVuln.writeup_id)
                .where(*servable_filter())
                .where(WriteupVuln.vuln_class.is_not(None))
                .group_by(WriteupVuln.vuln_class)
                .order_by(func.count(func.distinct(WriteupVuln.writeup_id)).desc())
            )
            .all()
        )
        return {"items": [
            {"vuln_class": name, "writeup_count": int(count)}
            for name, count in rows
        ]}

    @app.get("/v1/status")
    def get_status(session: Session = Depends(_session)):
        """Public, no key. A blocked source is visible here."""
        return build_status(session)

    @app.get("/", response_class=HTMLResponse)
    def get_website():
        """Website / demo page (T6). Static HTML; the search box and
        the corpus count call the live API from the browser, so the
        page never shows a stale copy of the data."""
        return HTMLResponse(_WEBSITE_HTML)

    @app.get("/llms.txt")
    def get_llms_txt(session: Session = Depends(_session)):
        """llms.txt index (Task 12 renders it; Task 16 serves it)."""
        return PlainTextResponse(
            render_llms_txt(session=session), media_type="text/plain")

    @app.post("/v1/submissions", status_code=201)
    def create_submission(
        body: SubmissionIn, session: Session = Depends(_session)
    ):
        """Enqueue a submission for human review. Never auto-indexes:
        the URL only enters a review row, never the writeups table."""
        existing = (
            session.execute(
                select(Submission)
                .where(Submission.url == body.url)
                .where(Submission.status == "in_review")
                .order_by(Submission.submitted_at)
            )
            .scalars()
            .first()
        )
        if existing is not None:
            return JSONResponse(
                content={"submission_id": existing.api_id,
                         "status": "in_review"},
                status_code=200,
            )
        row = Submission(url=body.url, notes=body.notes, status="in_review")
        session.add(row)
        session.flush()
        session.commit()
        return {"submission_id": row.api_id, "status": "in_review"}

    return app
