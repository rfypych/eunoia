"""Task 11: MCP server — 5 read-only tools + resources + prompt (§5.12).

Tests run against the dedicated ``eunoia_test`` database (same fixture
pattern as tests/test_search.py). The embedding model is a keyword stub
encoder — no test downloads weights. Tool calls go through the real MCP
protocol layer in-process (``MCPServer.call_tool``) and, for the
Streamable HTTP transport, through a TestClient ASGI app — no live
network, no real MCP client process.

Note on the brief's verbatim tests: they use an ``mcp_client`` fixture
with ``.call(name, args)`` and ``.tools``; this module provides exactly
that fixture, backed by the in-process server.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session
from starlette.testclient import TestClient

from eunoia.api.auth import create_api_key
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import url_hash
from eunoia.mcp_server import (
    McpToolError,
    build_mcp_server,
    create_streamable_http_app,
)
from eunoia.models import Base, Source, Writeup, WriteupSource, WriteupVuln

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"

NOW = datetime.now(timezone.utc)

_VOCAB = [
    "ssrf", "pdf", "parser", "spring", "boot", "tomcat", "log4j",
    "wordpress", "rce", "xss", "sqli", "deserialization", "java",
    "plugin", "remote", "code", "execution", "injection", "bypass",
    "auth", "framework", "server", "library",
]


class KeywordEncoder:
    """Deterministic 384-dim encoder; records every call."""

    def __init__(self):
        self.calls: list[list[str]] = []

    def encode(self, texts):
        self.calls.append(list(texts))
        vectors = []
        for text in texts:
            tokens = re.findall(r"[a-z0-9]+", text.lower())
            vec = [0.0] * 384
            for i, word in enumerate(_VOCAB):
                vec[i] = float(tokens.count(word))
            vectors.append(vec)
        return vectors


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
    with Session(engine) as s:
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


@pytest.fixture()
def encoder():
    return KeywordEncoder()


def _writeup(session, *, title, excerpt, program, vuln_class, cwe, cve=None,
             severity=None, bounty_verified=False, bounty_amount=None,
             language="en", status="active", days_ago=5):
    """Insert one writeup + its first vuln row; returns the Writeup."""
    url = f"https://example.com/reports/{uuid.uuid4().hex[:12]}"
    published = NOW - timedelta(days=days_ago)
    w = Writeup(
        canonical_url=url,
        url_hash=url_hash(url),
        title=title,
        excerpt=excerpt,
        language=language,
        status=status,
        published_at=published,
        disclosed_at=published,
        fetched_at=NOW,
        last_seen_at=NOW,
    )
    session.add(w)
    session.flush()
    session.add(WriteupVuln(
        writeup_id=w.id,
        vuln_class=vuln_class,
        cwe_id=cwe,
        cve_id=cve,
        cvss_score=9.8 if severity == "critical" else None,
        severity=severity,
        severity_source="hackerone" if severity else None,
        bounty_verified=bounty_verified,
        bounty_amount=bounty_amount,
        bounty_currency="USD" if bounty_amount else None,
        program=program,
    ))
    session.add(WriteupSource(
        writeup_id=w.id, source_id="hackerone", source_url=url,
    ))
    session.commit()
    return w


@pytest.fixture()
def seed(session):
    """Two active writeups + one retracted + one blocked source."""
    session.add(Source(
        id="hackerone", name="HackerOne Hacktivity", type="api",
        cursor_state={"blocked": "plan_gated_403"},
        last_poll_at=NOW - timedelta(hours=2),
        last_success_at=NOW - timedelta(days=1),
        consecutive_failures=3,
    ))
    ssrf = _writeup(
        session, title="SSRF via PDF parser in Spring Boot",
        excerpt="A PDF parser fetched internal URLs in a Spring Boot app.",
        program="Acme Spring", vuln_class="SSRF", cwe="CWE-918",
        cve="CVE-2022-22965", severity="critical",
        bounty_verified=True, bounty_amount=5000,
    )
    rce = _writeup(
        session, title="WordPress plugin RCE",
        excerpt="A WordPress plugin allowed remote code execution.",
        program="WP Plugin Co", vuln_class="RCE", cwe="CWE-94",
        severity="high",
    )
    retracted = _writeup(
        session, title="Retracted SSRF claim",
        excerpt="This claim was retracted by the author.",
        program="Acme Spring", vuln_class="SSRF", cwe="CWE-918",
        status="retracted",
    )
    session.commit()
    return {"ssrf": ssrf, "rce": rce, "retracted": retracted}


class McpTestClient:
    """Thin wrapper over ``MCPServer``: ``.call`` + ``.tools``."""

    def __init__(self, server):
        self.server = server

    def _unwrap(self, result):
        if result.is_error:
            text = result.content[0].text if result.content else ""
            raise McpToolError("TOOL_ERROR", text)
        structured = getattr(result, "structuredContent", None)
        if isinstance(structured, dict) and "result" in structured:
            return structured["result"]
        if isinstance(structured, dict):
            return structured
        return json.loads(result.content[0].text)

    def call(self, name, arguments=None):
        try:
            result = asyncio.run(
                self.server.call_tool(name, arguments or {})
            )
        except Exception as exc:  # UnexpectedToolError wraps the cause
            cause = getattr(exc, "__cause__", None)
            if isinstance(cause, McpToolError):
                raise cause
            raise
        return self._unwrap(result)

    @property
    def tools(self):
        return [t.name for t in asyncio.run(self.server.list_tools())]

    def read_resource(self, uri):
        result = asyncio.run(self.server.read_resource(uri))
        parts = []
        for item in result:
            content = item.content
            parts.append(
                content.decode() if isinstance(content, bytes) else content
            )
        return "\n".join(parts)

    def get_prompt(self, name, arguments=None):
        result = asyncio.run(
            self.server.get_prompt(name, arguments or {})
        )
        return [m.content.text for m in result.messages]


@pytest.fixture()
def mcp_client(session, encoder, seed):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    server = build_mcp_server(engine=engine, model=encoder)
    return McpTestClient(server)


@pytest.fixture()
def api_key(session, seed):
    plaintext, _row = create_api_key(session, owner="mcp-test")
    session.commit()
    return plaintext


# --- Verbatim brief tests ---------------------------------------------------


def test_search_writeups_default_limit_5(mcp_client):
    res = mcp_client.call("search_writeups", {"query": "ssrf spring"})
    assert len(res["results"]) <= 5


def test_no_write_tools_exist(mcp_client):
    assert "create_writeup" not in mcp_client.tools
    assert "delete_writeup" not in mcp_client.tools


# --- Tool inventory ---------------------------------------------------------


def test_exactly_the_five_read_only_tools(mcp_client):
    assert sorted(mcp_client.tools) == sorted([
        "search_writeups", "get_writeup", "get_writeup_skill",
        "list_vuln_classes", "list_programs", "check_freshness",
    ])


def test_tool_descriptions_state_the_scope_rule(mcp_client):
    tools = asyncio.run(mcp_client.server.list_tools())
    for tool in tools:
        assert "without explicit in-scope permission" in tool.description


# --- search_writeups --------------------------------------------------------


def test_search_writeups_returns_brief_shape(mcp_client, seed):
    res = mcp_client.call("search_writeups", {"query": "ssrf spring"})
    assert res["mode"] == "keyword"  # anon tier: keyword only
    assert res["limit"] == 5
    assert res["results"], "expected the seeded SSRF writeup"
    row = res["results"][0]
    assert row["writeup_id"] == seed["ssrf"].api_id
    for field in ("title", "excerpt", "canonical_url", "severity",
                  "bounty", "cwe_ids", "cve_ids", "score",
                  "score_breakdown", "match_reason", "verified",
                  "verified_label"):
        assert field in row, field
    assert "full_text" not in row  # metadata only, never full text
    assert row["excerpt"] is not None and len(row["excerpt"]) <= 300


def test_search_writeups_limit_20_clamps_to_10(mcp_client):
    res = mcp_client.call(
        "search_writeups", {"query": "ssrf spring", "limit": 20})
    assert res["limit"] == 10
    assert len(res["results"]) <= 10


def test_search_writeups_limit_3(mcp_client):
    res = mcp_client.call(
        "search_writeups", {"query": "ssrf spring", "limit": 3})
    assert res["limit"] == 3
    assert len(res["results"]) <= 3


def test_search_writeups_anon_semantic_is_forbidden(mcp_client):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call(
            "search_writeups", {"query": "ssrf", "mode": "semantic"})
    assert excinfo.value.code == "MODE_REQUIRES_KEY"


def test_search_writeups_anon_hybrid_is_forbidden(mcp_client):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call(
            "search_writeups", {"query": "ssrf", "mode": "hybrid"})
    assert excinfo.value.code == "MODE_REQUIRES_KEY"


def test_search_writeups_unknown_mode_is_rejected(mcp_client):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call(
            "search_writeups", {"query": "ssrf", "mode": "neural"})
    assert excinfo.value.code == "INVALID_ARGUMENT"


def test_search_writeups_severity_post_filter(mcp_client, seed):
    # Only the critical writeup survives a severity=critical filter.
    res = mcp_client.call(
        "search_writeups", {"query": "spring", "severity": "critical"})
    ids = [row["writeup_id"] for row in res["results"]]
    assert seed["ssrf"].api_id in ids
    assert seed["rce"].api_id not in ids


# --- get_writeup ------------------------------------------------------------


def test_get_writeup_returns_full_object(mcp_client, seed):
    obj = mcp_client.call("get_writeup", {"id": seed["ssrf"].api_id})
    assert obj["id"] == seed["ssrf"].api_id
    assert obj["title"] == "SSRF via PDF parser in Spring Boot"
    assert obj["vulnerability"]["classes"] == ["SSRF"]
    assert obj["vulnerability"]["cwe_ids"] == ["CWE-918"]
    assert obj["program"]["name"] == "Acme Spring"
    assert obj["bounty"]["verified"] is True
    assert obj["status"] == "active"
    assert obj["source_urls"], "expected at least one source URL"
    assert "technique_summary" in obj


def test_get_writeup_unknown_id_is_not_found(mcp_client):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call("get_writeup", {"id": "w_00000000000000000000000000000000"})
    assert excinfo.value.code == "NOT_FOUND"


# --- get_writeup_skill ------------------------------------------------------


def test_get_writeup_skill_returns_skill_text(mcp_client, seed):
    res = mcp_client.call("get_writeup_skill", {"id": seed["ssrf"].api_id})
    assert "berlatih dengan aman" in res["skill"]
    assert "authorization" in res["skill"].lower()
    assert res["id"] == seed["ssrf"].api_id


def test_get_writeup_skill_retracted_is_gone(mcp_client, seed):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call(
            "get_writeup_skill", {"id": seed["retracted"].api_id})
    assert excinfo.value.code == "GONE"


def test_get_writeup_skill_secret_refusal_is_not_gone(mcp_client, session):
    # A safety refusal is not a takedown: the secret-scan refusal
    # must not be mapped to GONE (410) like the R10 status gate.
    w = _writeup(
        session, title="SSRF with token ghp_" + "A" * 36,
        excerpt="A parser fetches URLs.",
        program="Acme Spring", vuln_class="SSRF", cwe="CWE-918",
    )
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call("get_writeup_skill", {"id": w.api_id})
    assert excinfo.value.code == "SECRET_FOUND"


# --- Facets -----------------------------------------------------------------


def test_list_vuln_classes(mcp_client):
    res = mcp_client.call("list_vuln_classes", {})
    classes = {row["vuln_class"]: row["writeup_count"] for row in res["items"]}
    assert classes.get("SSRF") == 1
    assert classes.get("RCE") == 1


def test_list_programs(mcp_client):
    res = mcp_client.call("list_programs", {})
    programs = {row["name"]: row["writeup_count"] for row in res["items"]}
    assert programs.get("Acme Spring") == 1
    assert programs.get("WP Plugin Co") == 1


# --- check_freshness --------------------------------------------------------


def test_check_freshness_surfaces_blocked_source(mcp_client):
    res = mcp_client.call("check_freshness", {})
    assert res["sources"], "expected the seeded source"
    row = res["sources"][0]
    assert row["id"] == "hackerone"
    assert row["status"] == "blocked"
    assert row["blocked"] is True
    assert row["blocked_reason"] == "plan_gated_403"
    assert row["lag_seconds"] is not None
    assert row["lag"] == row["lag_seconds"]


def test_check_freshness_unknown_source_is_not_found(mcp_client):
    with pytest.raises(McpToolError) as excinfo:
        mcp_client.call("check_freshness", {"source": "nope"})
    assert excinfo.value.code == "NOT_FOUND"


def test_check_freshness_filters_by_source(mcp_client):
    res = mcp_client.call("check_freshness", {"source": "hackerone"})
    assert [row["id"] for row in res["sources"]] == ["hackerone"]


# --- Resources --------------------------------------------------------------


def test_resource_writeup_markdown(mcp_client, seed):
    text = mcp_client.read_resource(f"writeup://{seed['ssrf'].api_id}")
    assert text.startswith("# SSRF via PDF parser in Spring Boot")
    assert seed["ssrf"].canonical_url in text
    assert "CWE-918" in text


def test_resource_writeup_skill(mcp_client, seed):
    text = mcp_client.read_resource(
        f"writeup://{seed['ssrf'].api_id}/skill")
    assert "berlatih dengan aman" in text


def test_resource_writeup_skill_retracted_is_gone(mcp_client, seed):
    with pytest.raises(Exception):
        mcp_client.read_resource(
            f"writeup://{seed['retracted'].api_id}/skill")


def test_resource_writeup_skill_secret_refusal_is_not_gone(
        mcp_client, session):
    # Same mapping as the tool: a secret-scan refusal surfaces as
    # SECRET_FOUND, never GONE. The SDK may wrap the resource error,
    # so the code is asserted anywhere in the exception chain.
    w = _writeup(
        session, title="SSRF with token ghp_" + "A" * 36,
        excerpt="A parser fetches URLs.",
        program="Acme Spring", vuln_class="SSRF", cwe="CWE-918",
    )
    with pytest.raises(Exception) as excinfo:
        mcp_client.read_resource(f"writeup://{w.api_id}/skill")
    chain = []
    exc = excinfo.value
    while exc is not None:
        chain.append(str(exc))
        exc = exc.__cause__ or exc.__context__
    assert any("SECRET_FOUND" in part for part in chain)
    assert not any(part.startswith("GONE") for part in chain)


# --- Prompt -----------------------------------------------------------------


def test_prompt_learn_from_writeup(mcp_client, seed):
    messages = mcp_client.get_prompt(
        "learn-from-writeup", {"id": seed["ssrf"].api_id})
    assert messages, "expected at least one prompt message"
    joined = "\n".join(messages)
    assert seed["ssrf"].api_id in joined
    assert "SSRF" in joined
    assert "without explicit in-scope permission" in joined
    assert "lab" in joined.lower()


def test_prompt_learn_from_writeup_unknown_id(mcp_client):
    with pytest.raises(Exception):
        mcp_client.get_prompt(
            "learn-from-writeup",
            {"id": "w_00000000000000000000000000000000"})


# --- Streamable HTTP transport (stateless) ----------------------------------


def _rpc_payload(method, params, rpc_id=1):
    return {
        "jsonrpc": "2.0", "id": rpc_id, "method": method,
        "params": {
            **params,
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    }


def _http_headers(method, name=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": "2026-07-28",
        "Mcp-Method": method,
    }
    if name:
        headers["Mcp-Name"] = name
    return headers


@pytest.fixture()
def http_client(session, encoder, seed):
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    server = build_mcp_server(engine=engine, model=encoder)
    app = create_streamable_http_app(
        server, allowed_hosts=["testserver", "127.0.0.1", "localhost"])
    with TestClient(app, raise_server_exceptions=True) as client:
        yield client


def test_http_tools_call_without_initialize(http_client):
    # 2026-07-28 is stateless: no initialize handshake is needed first.
    resp = http_client.post(
        "/mcp",
        json=_rpc_payload("tools/call", {
            "name": "search_writeups",
            "arguments": {"query": "ssrf spring"},
        }),
        headers=_http_headers("tools/call", "search_writeups"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "result" in body, body
    assert body["result"]["isError"] is False
    content = body["result"]["content"][0]["text"]
    assert "ssrf" in content.lower()


def test_http_tools_list_without_initialize(http_client):
    resp = http_client.post(
        "/mcp",
        json=_rpc_payload("tools/list", {}, rpc_id=2),
        headers=_http_headers("tools/list"),
    )
    assert resp.status_code == 200
    names = [t["name"] for t in resp.json()["result"]["tools"]]
    assert "search_writeups" in names
    assert "create_writeup" not in names


def test_http_keyed_hybrid_search(http_client, api_key):
    resp = http_client.post(
        "/mcp",
        json=_rpc_payload("tools/call", {
            "name": "search_writeups",
            "arguments": {"query": "ssrf spring", "mode": "hybrid"},
        }),
        headers={
            **_http_headers("tools/call", "search_writeups"),
            "Authorization": f"Bearer {api_key}",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["isError"] is False, body


def test_http_bad_key_is_tool_error_not_500(http_client):
    resp = http_client.post(
        "/mcp",
        json=_rpc_payload("tools/call", {
            "name": "search_writeups",
            "arguments": {"query": "ssrf spring"},
        }),
        headers={
            **_http_headers("tools/call", "search_writeups"),
            "Authorization": "Bearer bad-key",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["result"]["isError"] is True, body
    assert "UNAUTHORIZED" in body["result"]["content"][0]["text"]
