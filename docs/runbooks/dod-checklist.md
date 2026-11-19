# Eunoia — Definition of Done checklist

Measured 19 Nov 2026. Every checked item cites measured numbers,
not assertions. Anything unmet stays `[]` with the reason. The
items follow the ten checks a release must meet; the previous
checklist (18 Nov 2026, golden corpus) is superseded — its
measurements are kept in `CHANGELOG.md` 0.1.0 and in
`docs/reports/corpus-500.md`.

- [ ] 1. Install one command works from a clean machine, hosted
  mode, no local database.
  Reason: the checkout install works and is measured — `pip install .`
  cold-cache 4 s / 16 MB venv, `eunoia doctor` OK (507 writeups
  active, 6 tools) — but the single PyPI command
  `pipx install eunoia-agents` does not work yet: the package is
  not on PyPI, and publishing is an operator decision.
- [x] 2. Website/demo live at the root, search works without login.
  Evidence: `GET /` returns 200 HTML (verified live 19 Nov 2026,
  4063 bytes), the search box calls the live `/v1/search`, and a
  CSRF search returns a real writeup
  (`hackerone.com/reports/3882740`, score 0.6745). No login anywhere
  on the page.
- [x] 3. README and docs complete, all links live, no invented contact wording.
  Evidence: docs index (`docs/index.md`) maps every guide
  (install, CLI, API, MCP, troubleshooting, roadmap, FAQ); link
  checks pass (`tests/test_docs.py`, `tests/test_readme.py`);
  no invented contact string appears in any public doc; the DMCA
  email is recorded as not yet set, with no fake address printed.
- [ ] 4. MCP documented, `tools/list` works via a real client, 6 tools, stateless.
  Reason: `mcp.json` and `server.json` exist, per-client configs
  for Claude Code, Codex and Cursor exist, and `tools/list`
  returns exactly the 6 tools (verified 19 Nov 2026 with the
  official Python MCP SDK client, stateless 2026-07-28) — but the
  server has not been submitted to the Official MCP Registry;
  submission needs the operator's identity decision.
- [x] 5. Corpus at least 500 real writeups, unclassified under 10%, recall@10 at least 0.90 on the real corpus, latency recorded.
  Evidence: 507 active writeups, 507/507 with embeddings,
  45 unclassified (8.9%) at the 19 Nov 2026 measurement;
  recall@10 0.9048 on 21 queries (pre-test 1.00, mid-test 0.714),
  p50 46.89 ms, p95 78.45 ms. Method and misses are in
  `docs/reports/corpus-500.md`. Margin is thin (19/21 — one more
  miss would fall below 0.90) and mid-test is the weak point.
- [x] 6. Full suite passes in CI and from a clean checkout.
  Evidence: CI green on GitHub commit 3731a3a (19 Nov 2026, both
  jobs: `test` and `no-db`); full suite 496 passed locally
  on 19 Nov 2026 from this checkout (`bash scripts/setup_dev.sh`
  then `pytest -q`).
- [x] 7. Three showcases with evidence and repeatable numbers.
  Evidence: `docs/showcases.md` — pre-test CSRF planning,
  mid-test blind SQL injection (same candidate under both
  rankings), and install/doctor end-to-end from a fresh virtual
  environment (7.1 s install, 1.9 s doctor, 507 writeups active,
  6 MCP tools). Every number is as measured live on 19 Nov 2026,
  with the exact request to re-run it and the limitations stated.
- [ ] 8. Safety and legal: real DMCA email, takedown end-to-end passes, secrets scan 0, no payloads.
  Reason: the DMCA agent email is not yet set (operator decision),
  so the takedown end-to-end test has not been run. No payloads
  are served by design: skills and excerpts contain technique
  patterns only (see the transparency note).
- [ ] 9. Poller runs 7 days unattended, lag at most 1 hour, `error_rate` is a real number.
  Reason: the 7-day window started 19 Nov 2026 02:49 UTC and ends
  around 26 Nov 2026 — it cannot be finished early. `error_rate`
  in `/v1/status` is still `null`: there is no poll-attempt
  counter yet, so no number is invented.
- [ ] 10. Tagged release, changelog, LICENSE MIT, GitHub head equals local HEAD.
  Reason: LICENSE MIT and the changelog exist, but no release tag
  exists yet, and remote `main` is 3731a3a (19 Nov 2026) while the
  newest work (through the showcases, commit 3568bb4) is on
  the `rea-standard` branch and is not on `main` yet.

## Known gaps / launch blockers (not hidden)

- DMCA agent email is not yet set — must be replaced with a real
  operator contact before public launch. No fake address is
  printed anywhere in the repo.
- The `eunoia-agents` package is not on PyPI yet; the first PyPI
  release is blocked on the operator publishing it.
- The MCP server has not been submitted to the Official MCP
  Registry; submission needs the operator's identity decision.
- DoD 9 is unmet: no 7-day unattended poller run has happened yet.
- Recall@10 0.9048 was measured on the real 507-writeup corpus on
  19 Nov 2026; the 0.9300 figure is a synthetic-corpus measurement
  kept as a regression fixture only.
- No production LLM judge is wired: exploit / credential-use /
  state-changing actions require a judge pass AND recorded human
  approval.
- `error_rate` in `/v1/status` is honestly `null`: there is no
  poll-attempt counter yet.
