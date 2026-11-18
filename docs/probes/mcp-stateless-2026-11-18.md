# Probe: MCP stateless revision 2026-07-28

Date: 2026-11-18. Answers spec §9 Q2 (final-product-ready-to-build.md).

## Verdict

**Verified.** The 2026-07-28 revision of the Model Context Protocol is
stateless: no `initialize` handshake, no `Mcp-Session-Id`, every request
self-describing. Confirmed against the official specification at
modelcontextprotocol.io (opened directly, 2026-11-18) and against the
Python SDK installed in this repo (`mcp` 2.3.0,
`LATEST_PROTOCOL_VERSION == "2026-07-28"`).

## What the official spec says

Source: https://modelcontextprotocol.io/specification/2026-07-28
(crawled 2026-11-18 17:05 UTC; page "Updated: 2026-11-16T04:15:22.123Z").

Base Protocol key details, verbatim from the page:

- "Stateless, self-contained requests"
- "Per-request capability negotiation"
- Extensions are "negotiated through capabilities that clients declare
  on each request and servers declare in their `server/discover` result."

## What the secondary sources add (consistent, all quoting the official changelog / release post)

- The 2026-07-28 revision is the largest since launch; the official
  release post (David Soria Parra and Den Delimarsky, July 2026) says
  "MCP is transforming from a bidirectional stateful protocol into a
  request/response stateless protocol".
- Removed: `initialize` / `notifications/initialized` handshake
  (SEP-2575), `Mcp-Session-Id` header and protocol-level sessions
  (SEP-2567), the standalone HTTP GET stream, SSE resumability,
  `ping`, `logging/setLevel`, `notifications/roots/list_changed`.
- Added: `server/discover` (servers MUST implement it), per-request
  `_meta` (`io.modelcontextprotocol/protocolVersion`,
  `.../clientCapabilities`, `.../clientInfo`), required Streamable
  HTTP routing headers `MCP-Protocol-Version`, `Mcp-Method`,
  `Mcp-Name`, `subscriptions/listen` for change notifications, and
  Multi Round-Trip Requests (SEP-2322) for elicitation/sampling.
- Deprecated (minimum twelve-month window): Roots, Sampling, Logging,
  the HTTP+SSE transport, OAuth Dynamic Client Registration.
- Previous revision: 2025-11-25. A client built for 2026-07-28 falls
  back to the handshake-based protocol when it meets an older server.

Sources: https://betterstack.com/community/guides/ai/mcp-stateless/,
http://dev.to/fabwaseem/stateless-mcp-servers-what-the-2026-07-28-spec-changed-and-how-to-migrate-5ccl,
https://www.osmondvanhemert.nl/posts/260730-mcp-stateless-protocol-spec/,
https://agentic-academy.ai/posts/mcp-2026-07-28-stateless-rewrite/,
https://www.querynow.com/ai-agents/mcp/what-is-mcp,
https://kanerika.com/blogs/model-context-protocol/

## What this implementation does with it

- `src/eunoia/mcp_server.py` builds the server on the MCP Python SDK
  2.3.0 (`MCPServer`, `streamable_http_app(stateless_http=True)`).
  `LATEST_PROTOCOL_VERSION` from the SDK is `"2026-07-28"`; the
  server speaks that revision.
- Transport: Streamable HTTP (`POST /mcp`, remote) or stdio (local
  wrapper). No session state is kept server-side: every tool call
  opens its own DB session and resolves auth + rate limit per request.
- Verified in-process and over HTTP in `tests/test_mcp.py`:
  `tools/call` and `tools/list` return 200 with no `initialize`
  handshake first, with `_meta` carrying protocolVersion
  `2026-07-28` and the `Authorization` header reaching the tool.
- `TransportSecuritySettings(allowed_hosts=[...])` is the
  DNS-rebinding allowlist; deployment must list its own public
  hostname. Default is loopback only.
- Auth for remote use is the same API-key scheme as REST (spec §5.5).
  OAuth 2.1 is NOT implemented: the spec makes it the authorization
  framework for remote servers, but v1 is single-tenant with API
  keys, and no OAuth server is invented for it (see the plan's
  Task 11 text). Multi-tenant hosted deployment would need OAuth
  2.1; that is a post-MVP decision.

## Caveats

- The spec page itself does not carry a changelog section on the
  overview page; the removed/added item list above comes from the
  official changelog and release post as quoted by the secondary
  sources, which agree with each other and with the SDK's behavior.
- "Stateless" is protocol-level: the server still reads the database
  on every request. There is no per-client session store, no sticky
  routing, and no `Mcp-Session-Id` is minted or echoed.
