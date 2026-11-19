# Roadmap

What is done, what is still open, and what blocks it. Dates are
measurement dates, not promises.

## Done (19 Nov 2026)

- **Hosted API + MCP live.** API on port 10004, MCP on port
  10005, worker polling HackerOne every 15 minutes, all under
  supervisord on the operator box.
- **Corpus 507 real writeups.** 507 active, 507/507 with
  embeddings, 45 unclassified (8.9%) at the 19 Nov 2026
  measurement. Recall@10 0.9048 on 21 queries (pre-test 1.00,
  mid-test 0.714), p50 46.89 ms, p95 78.45 ms. See
  [Corpus report](reports/corpus-500.md).
- **Website/demo live at the API root.** `GET /` returns HTML
  200 with a search box calling the live `/v1/search`.
- **One-command checkout install.** `pip install .` then
  `eunoia setup` / `eunoia doctor`; cold-cache install 4 s,
  16 MB venv. Installable skills via `eunoia skills install`.
- **MCP discoverable.** `mcp.json`, `server.json`, per-client
  configs (Claude Code, Codex, Cursor), a Claude Code plugin,
  and [MCP docs](mcp.md). `tools/list` returns the 6 tools.
- **Three showcases with evidence.** See [Showcases](showcases.md).
- **Legal basis.** MIT license, security policy, contributing
  guide, changelog. CI green on GitHub (`main` 3731a3a,
  19 Nov 2026).
- **Structured docs.** This index and the guides under it.

## Open

- **PyPI release (`eunoia-agents`).** Blocked on the operator
  publishing the package. The name is free (checked 2026-11-19).
  Until then the one-command install is `pip install .` from a
  checkout, and `pipx install eunoia-agents` does not work.
- **MCP Registry submission.** The server is documented and its
  `server.json` is ready, but it has not been submitted to the
  Official MCP Registry. Blocked on the operator's identity
  decision (publishing under `io.github.rfypych`).
- **DMCA agent email.** Not yet set — no address has been
  published. Blocked on the operator providing a real contact.
  Until then, takedown requests go via a GitHub issue (see
  [Takedown policy](policies/takedown.md)). The takedown
  end-to-end test is blocked on the same decision.
- **Poller 7-day run.** The window started 19 Nov 2026 02:49 UTC
  and ends around 26 Nov 2026. It cannot be finished early.
- **`error_rate` in `/v1/status`.** Still `null`: there is no
  poll-attempt counter yet, so no number is invented.
- **Release 0.2.0 (tagged).** No release tag exists yet. Remote
  `main` is 3731a3a (19 Nov 2026); the newest work is on the
  `rea-standard` branch and is not on `main` yet.
- **Domain and trademark.** The Eunoia name, and whether the
  website uses the box IP, a subdomain, or a new domain, are
  unchecked.
- **Production LLM judge.** None wired. Exploit /
  credential-use / state-changing actions require a judge pass
  AND recorded human approval.
