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

MCP endpoint: [mcp](http://129.150.57.82:10005/mcp). The server exposes 6 read-only tools: `search_writeups`, `get_writeup`, `get_writeup_skill`, `list_vuln_classes`, `list_programs`, `check_freshness`, plus 2 resource templates and 1 prompt. Local stdio mode is also available: `python -m eunoia.mcp_server`. Client-specific config files and registry listing are planned work, not done yet.

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
| A class skill | `get_writeup_skill(id="...")` | A `SKILL.md` generated from that writeup |
| What is fresh | `check_freshness()` | Last poll, lag, and source health |

Current scope, measured 2026-11-19: **50 real HackerOne writeups, Java/Spring only**, polled every 15 minutes. The corpus is small and 18 of the 50 writeups are still unclassified (36%); growing it to 500 with under 10% unclassified is planned work.

## What Eunoia does not do

- It is not a scanner. It never probes, scans, or attacks a target.
- It contains no payload library and executes no exploits.
- It is not a full-text mirror. It stores metadata and links to the canonical public disclosure; read the writeup at its source.
- It does not test anything live. Every hypothesis it returns still needs explicit in-scope permission before any testing.
- It does not invent findings. Results are ranked past writeups with scores and links, not generated vulnerabilities.

## Measured results (2026-11-19)

Measured read-only on the real production corpus of 50 writeups, 20 queries, 2026-11-19. Production was not changed by the measurement.

- **Recall@10: 0.90** overall (pre-test 1.00, mid-test 0.75). The 3 misses were all mid-test.
- **Latency: p50 20.34 ms, p95 32.66 ms.**
- **Corpus: 50 writeups, 50/50 with embeddings, 0 quarantined rows in the top 10.**
- **Source health: HackerOne ok, 0 consecutive failures.** Check the current numbers at [status](http://129.150.57.82:10004/v1/status).

Honest limits, same date: recall was measured on a 50-writeup corpus, so it is not a launch-grade number yet. The 7-day poller window started 2026-11-19 02:49 UTC and ends around 2026-11-26. The one-command hosted install and the website/demo are not yet live; until then, use the hosted API and MCP above.

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
- [Contributing](CONTRIBUTING.md) — setup, TDD, and the no-payload rule.
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
Not yet live. The API root still returns 404; the website/demo is planned work.

**Is there a one-command install?**
Not yet. The hosted API and MCP above are the way to try it today; a one-command setup is planned work.

**What is the licence?**
MIT. See [LICENSE](LICENSE).

## License

MIT — see [LICENSE](LICENSE).
