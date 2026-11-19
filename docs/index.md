# Documentation index

Start here. The flow a new reader follows is: install the client,
run the first query, then read a showcase.

1. [Install](install.md) — get the client on your machine.
2. Run the first query — `curl "http://129.150.57.82:10004/v1/search?q=CSRF&limit=2"`,
   or point an agent at the MCP server (see [MCP](mcp.md)).
3. [Showcases](showcases.md) — three real cases with evidence:
   pre-test CSRF planning, mid-test blind SQL injection, and
   install/doctor end-to-end.

## Guides

- [Install](install.md) — checkout install, development setup,
  and the PyPI status.
- [CLI](cli.md) — `setup`, `doctor`, `update`, `skills install`.
- [API](api.md) — endpoints, auth tiers, limits, and errors.
- [MCP](mcp.md) — connect an agent over the hosted MCP server
  (6 read-only tools, 2 resource templates, 1 prompt).
- [Troubleshooting](troubleshooting.md) — the failures people
  actually hit, and the fix for each.
- [Roadmap](roadmap.md) — what is done, what is still open, and
  what blocks it.

## Reference

- [Showcases](showcases.md) — three real cases with evidence.
- [Runbook](runbook.md) — how the service runs: poll loop, KEV
  sync, API keys, recovery.
- [Transparency](transparency.md) — what is served, what is not,
  and the open items.
- [Takedown policy](policies/takedown.md) — how a disclosure is
  removed on request.
- [Definition of Done](runbooks/dod-checklist.md) — the ten
  checks a release must meet, with measured evidence.
- [FAQ](../README.md#faq) — is it a scanner, do I need a key,
  where does the data come from, is there a website.
- [Changelog](../CHANGELOG.md) — 0.1.0 (2026-11-19) and
  unreleased changes.
- [Contributing](../CONTRIBUTING.md) — setup and the no-payload rule.
- [Security](../SECURITY.md) — how to report a vulnerability.
- [Corpus report](reports/corpus-500.md) — the 507-writeup
  measurement (19 Nov 2026): recall, latency, classification,
  and the scope finding.

## Entry points (live)

- Website/demo: <http://129.150.57.82:10004/>
- API status: <http://129.150.57.82:10004/v1/status>
- API schema: <http://129.150.57.82:10004/api/v1/openapi.json>
- Machine-readable index: <http://129.150.57.82:10004/llms.txt>
- MCP server: <http://129.150.57.82:10005/mcp>
- Source: <https://github.com/rfypych/eunoia>
