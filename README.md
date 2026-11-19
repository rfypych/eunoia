# Eunoia

**Eunoia is an external brain for autonomous pentesting AI agents: stack in, evidence-backed attack plan out.**

It is a metadata-plus-link registry of public, authorized bug-bounty writeups, enriched with CVE data. An agent asks Eunoia for the most similar past writeups twice: before testing, to build a prioritised attack plan from recon, and mid-test, when it is stuck or finds a suspicious candidate. The agent never queries HackerOne, Bugcrowd, or Medium directly; Eunoia ingests those sources server-side and the agent queries Eunoia.

Built for autonomous pentesting agents and the humans who run them. Humans use the REST API; agents use the read-only MCP server.

## Try it now (no install)

The hosted API is live. No key is needed for keyword search.

```bash
curl http://129.150.57.82:10004/v1/status
curl "http://129.150.57.82:10004/v1/search?q=CSRF&limit=2"
```

Real search output, 2026-11-19:

```json
{
  "writeup_id": "w_01a1f1a6533177e99904437453565607",
  "title": "All stored Slack and Teams credentials can be deleted via Management Console CSRF",
  "canonical_url": "https://hackerone.com/reports/3882740",
  "severity": "medium",
  "cwe_ids": ["CWE-352"],
  "score": 0.6746
}
```

Live status: [status](http://129.150.57.82:10004/v1/status) · writeups: [writeups](http://129.150.57.82:10004/v1/writeups) · machine-readable index: [llms.txt](http://129.150.57.82:10004/llms.txt) · API schema: [OpenAPI](http://129.150.57.82:10004/api/v1/openapi.json)

## Install (one command)

Works today, from a checkout of [github.com/rfypych/eunoia](https://github.com/rfypych/eunoia):

```bash
pip install .
eunoia setup
eunoia doctor
```

`eunoia setup` detects Claude Code, Codex and Cursor, shows the config change, asks before writing it, and backs up any config it replaces (the first backup is `<file>.bak`, later ones are timestamped). `eunoia doctor` checks the hosted API and MCP server with no local database.

The install is light: the `eunoia` CLI uses only the standard library, so `pip install .` has no heavy dependencies. Cold-cache install in a fresh virtual environment, measured 2026-11-19: see "Measured results" below. The server dependencies are the optional `server` extra (`pip install ".[server]"`), and the embedding model is the separate `embed` extra (`pip install "eunoia-agents[embed]"`, which pulls torch).

After the first PyPI release, the one command will be:

```bash
pipx install eunoia-agents
```

That command does not work yet: the package is not on PyPI yet (checked 2026-11-19: the name `eunoia` is taken by another project, so the package is `eunoia-agents`). The first PyPI release is blocked on the branch being pushed to GitHub (T2) and on the package being published — until then, install from a checkout as above.

### Installable skills

After `pip install .`, install the skills into your agents:

```bash
eunoia skills install
eunoia skills list
```

This writes the registry skill (`writeup-registry`) plus one skill per real vuln class (`ssrf-fundamentals`, `xss-fundamentals`, ...) into each detected agent's skills directory:

| Agent | Skills directory |
| --- | --- |
| Claude Code | `~/.claude/skills/<name>/SKILL.md` |
| Codex | `~/.agents/skills/<name>/SKILL.md` |
| Cursor | `~/.cursor/skills/<name>/SKILL.md` |

The registry skill ships with the package; per-class skills are fetched live from the hosted API at install time, so re-running the install refreshes them. `unclassified` is never installed: there is no technique to teach for a class that means "not yet classified". The install shows the plan, asks before writing, and backs up any skill it replaces.

Skill-only vs MCP:

| What | Needs the MCP server? | How it works |
| --- | --- | --- |
| Installed skills (`writeup-registry`, `*-fundamentals`) | No | File-based `SKILL.md`; the agent follows them by calling the REST API (`GET /v1/search`, `GET /v1/writeups/{id}/skill.md`). No MCP server, no local database. |
| Per-writeup skill in a live session | No, but faster with MCP | `GET /v1/writeups/{id}/skill.md` over REST, or the `get_writeup_skill` MCP tool — same text, two transports. |

Worked example, pre-test: an agent pentesting a Java/Spring app reads the `writeup-registry` skill, searches once per technology, and finds the CSRF writeup [All stored Slack and Teams credentials can be deleted via Management Console CSRF](https://hackerone.com/reports/3882740) (CWE-352, medium). It fetches that writeup's skill at http://129.150.57.82:10004/v1/writeups/w_01a1f1a6533177e99904437453565607/skill.md and builds the CSRF hypothesis from the pattern, not from a payload.

Worked example, mid-test: stuck on a suspicious SSRF candidate, the agent re-queries with `mid_test=true` and finds [SSRF in Portainer app lead to access to Internal Docker API without Auth](https://hackerone.com/reports/366638) (CWE-918, critical, $500 verified). It reads the `ssrf-fundamentals` skill and that writeup's skill, then verifies the candidate in its own lab before treating it as a finding.

## Quick start

### For an agent: connect over MCP

Point your MCP client at the hosted server (Streamable HTTP, stateless, `POST /mcp`):

```json
{
  "mcpServers": {
    "eunoia": {
      "type": "http",
      "url": "http://129.150.57.82:10005/mcp"
    }
  }
}
```

MCP endpoint: [mcp](http://129.150.57.82:10005/mcp). The server exposes 6 read-only tools: `search_writeups`, `get_writeup`, `get_writeup_skill`, `list_vuln_classes`, `list_programs`, `check_freshness`, plus 2 resource templates and 1 prompt. Local stdio mode is also available: `python -m eunoia.mcp_server`. Ready-made configs: [mcp.json](mcp.json) (generic), [server.json](server.json) (Official MCP Registry format), per-client files under `clients/` (Claude Code, Codex, Cursor), and a Claude Code plugin under `plugins/claude-code/` — see [docs/mcp.md](docs/mcp.md). The server has not been submitted to the Official MCP Registry yet; submission needs the operator's identity decision.

Example agent prompt:

> You are pentesting a Java/Spring web app. Before testing, call `search_writeups` once per main technology (limit 5 each) and build a prioritised attack plan from the results, citing the writeup link for every hypothesis. Mid-test, when you are stuck or find a suspicious candidate, call `search_writeups` again with `mid_test=true` (limit 3) and adapt the plan. Never test a target without explicit in-scope permission.

### For a human: query the API

```bash
# Pre-test: plan from recon (default ranking)
curl "http://129.150.57.82:10004/v1/search?q=SQL+injection&limit=5"

# Mid-test: stuck, or a suspicious candidate (mid-test ranking)
curl "http://129.150.57.82:10004/v1/search?q=IDOR&lookup=mid_test&limit=3"
```

Anonymous callers get keyword mode only, limit up to 10 (default 5). Semantic and hybrid modes need an API key.

## What you can search

| Ask for | How | Notes |
| --- | --- | --- |
| A technique or keyword | `search_writeups(query="CSRF")` or `GET /v1/search?q=CSRF` | Keyword mode without a key |
| A stack | `search_writeups(query="...", tech=["Java", "Spring"])` | One call per main technology, pre-test |
| A vulnerability class | `search_writeups(vuln_class="IDOR")` | Classes include IDOR, XSS, SQLi, RCE, Path Traversal, XXE |
| A weakness | `search_writeups(cwe="CWE-352")` | CWE ids, normalised from the source |
| A single writeup | `get_writeup(id="...")` | Full metadata plus the canonical source link |
| A writeup skill | `get_writeup_skill(id="...")` or `GET /v1/writeups/{id}/skill.md` | A `SKILL.md` generated from that writeup |
| A class skill | `GET /v1/vuln-classes/{class}/skill.md` | Aggregate of the best verified writeups in that class |
| What is fresh | `check_freshness()` | Last poll, lag, and source health |

Current scope, measured 2026-11-19: **507 real HackerOne writeups, all disclosed reports (not Java/Spring-only)**, polled every 15 minutes. 45 of the 507 writeups are still unclassified (8.9%).

## What Eunoia does not do

- It is not a scanner. It never probes, scans, or attacks a target.
- It contains no payload library and executes no exploits.
- It is not a full-text mirror. It stores metadata and links to the canonical public disclosure; read the writeup at its source.
- It does not test anything live. Every hypothesis it returns still needs explicit in-scope permission before any testing.
- It does not invent findings. Results are ranked past writeups with scores and links, not generated vulnerabilities.

## Measured results (2026-11-19)

Measured read-only on the live production corpus of 507 writeups, 21 queries, 2026-11-19. Production was not changed by the measurement.

- **Recall@10: 0.9048** overall (pre-test 1.00, mid-test 0.714). The 2 misses were both mid-test, both 2022 reports with low severity and no CVSS.
- **Latency: p50 46.89 ms, p95 78.45 ms.**
- **Cold-cache install (2026-11-19):** `pip install .` in a fresh virtual environment took 4 s, venv 16 MB (base CLI only, stdlib-only; it was 24 min / 5.8 GB when torch was a base dependency). `pip install ".[dev,server]"` cold took 65 s, venv 121 MB, with no torch installed. `eunoia doctor` from the cold base venv: OK (50 writeups active, 6 tools).
- **Corpus: 507 writeups, 507/507 with embeddings, 45 unclassified (8.9%).**
- **Source health: HackerOne ok, 0 consecutive failures.** Check the current numbers at [status](http://129.150.57.82:10004/v1/status).

Previous measurement, same date, on the 50-writeup corpus: recall@10 0.90 (pre-test 1.00, mid-test 0.75), p50 20.34 ms, p95 32.66 ms; the 3 misses were all mid-test.

Honest limits, same date: recall was measured on a 507-writeup corpus, so it is not a launch-grade number yet, and the production margin is thin (19/21 — one more miss would fall below 0.90). The 7-day poller window started 2026-11-19 02:49 UTC and ends around 2026-11-26. The website/demo is live at http://129.150.57.82:10004/ — search from the page calls the live API. The `eunoia-agents` package is not on PyPI yet; the install command that works today is `pip install .` from a checkout (see Install above).

## Development setup (one command)

From a clean checkout, run:

```bash
bash scripts/setup_dev.sh
.venv/bin/python -m pytest -q
```

`setup_dev.sh` is idempotent and safe to re-run. It creates the `.venv` (Python 3.12) and installs the package, brings up Postgres 16 + pgvector (Docker Compose with `pgvector/pgvector:pg16` when Docker is available, otherwise the local Postgres 16 cluster, rebuilding pgvector from `~/pgvector-build` when it is older than 0.7.0), creates the dev (`eunoia`) and test (`eunoia_test`) databases, runs migrations on both, and seeds the dev database.

## Test database

Tests run against a dedicated `eunoia_test` database, never the dev database. `setup_dev.sh` creates it; the lower-level scripts `scripts/setup_dev_db.sh` / `scripts/setup_test_db.sh` still exist for the local-cluster path. If the test database is missing, `pytest tests/test_models.py` fails with a message pointing at that script.

## Docs

- [Runbook](docs/runbook.md) — how the service runs, including the worker and supervisord setup.
- [Transparency](docs/transparency.md) — what is served, what is not, and the open items.
- [Takedown policy](docs/policies/takedown.md) — how a disclosure is removed on request.
- [DoD checklist](docs/runbooks/dod-checklist.md) — the Definition of Done, with measured evidence.
- [Changelog](CHANGELOG.md) — 0.1.0 (2026-11-19) and unreleased changes.
- [Contributing](CONTRIBUTING.md) — setup and the no-payload rule.
- [Security](SECURITY.md) — how to report a vulnerability.
- Source: [github.com/rfypych/eunoia](https://github.com/rfypych/eunoia)

## FAQ

**Is Eunoia a scanner?**
No. It is a lookup service over past public writeups. It never sends traffic to a target.

**Do I need an API key?**
No, for keyword search over the API or MCP. Semantic and hybrid search need a key.

**Where does the data come from?**
Public HackerOne Hacktivity disclosures, enriched with NVD/CVE data. Each result links to its canonical source.

**Can I use it for a real pentest?**
Only with explicit permission for a target in scope. Eunoia gives hypotheses with evidence; it does not authorise testing.

**Is there a website or demo page?**
Yes, live at http://129.150.57.82:10004/ — a search box that calls `/v1/search`, an example search on load, and links to the API docs, `llms.txt`, and MCP.

**Is there a one-command install?**
Yes, from a checkout: `pip install .`, then `eunoia setup`. The single PyPI command `pipx install eunoia-agents` will work after the first PyPI release, which is blocked on the branch being pushed and the package being published.

**What is the licence?**
MIT. See [LICENSE](LICENSE).

## License

MIT — see [LICENSE](LICENSE).
