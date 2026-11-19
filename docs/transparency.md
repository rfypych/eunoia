# Eunoia — Transparency note

What this registry is, what it is not, and where it differs from
its original design. Values that do not exist yet are stated as
"none yet" rather than invented. Last updated 19 Nov 2026.

## What it is

A metadata index + links for public, authorized vulnerability
disclosures, built for AI pentesting agents to query. It is not a
full-text mirror: skill bodies contain technique patterns and
vulnerability classes only — no verbatim payloads against live
targets, no target URLs, no credentials. Every skill carries an
authorization warning and ends with safe-practice guidance.

## How it differs from the original design

- **API base path is `/v1/...`, not `/api/v1/...`.** The only
  `/api/v1/` path is the OpenAPI document itself
  (`/api/v1/openapi.json`).
- **Submission body is `{url, notes?}`.** The declaration that
  submitted content is public/authorized cannot be given by the
  submitter in this shape, so it is not requested. Risk is
  bounded: a submission lands in `in_review` only and is never
  auto-indexed.
- **REST search limit is max 10, not 20.** The agent loop never
  takes more than 10 results; the response reports the effective
  limit.
- **Search serves `active` + `updated` writeups.** The serving
  gate is shared (`src/eunoia/safety/serving.py`): a writeup is
  servable only when its status is `active` or `updated` and it
  passes the quality gate.
- **MCP `search_writeups` defaults to keyword mode for anonymous
  callers**, even though the tool signature lists hybrid first.
  Anonymous results without a mode argument only work in keyword
  mode; keyed callers get hybrid, and asking for `semantic` or
  `hybrid` without a key returns 403 `MODE_REQUIRES_KEY`.
- **The Definition of Done is checked item by item with
  evidence.** An unmet item stays unchecked with its reason
  (see `docs/runbooks/dod-checklist.md`); nothing is checked by
  assertion alone.
- **Reranking is not implemented.** `rerank=true` raises
  `NotImplementedError` in the search engine and is mapped to 501
  (never 500) by REST and MCP, until rerank latency is measured.

## Serving boundary (list vs detail)

Detail endpoints (REST `GET /v1/writeups/{id}`, `.md`, `skill.md`;
MCP `get_writeup`, `get_writeup_skill`, resources
`writeup://{id}`, prompt `learn-from-writeup`) serve only
servable writeups: status `active`/`updated` AND
`quality_passed is not False`. Anything else is 410 Gone (REST)
or `GONE` (MCP); a skill blocked by the secret scan is 503 /
`SECRET_FOUND`, never 410. Search and the list endpoint apply
the same gate. The list endpoint with an explicit
`status=retracted` filter still returns retracted rows: that is
a pinned review-queue query surface, not agent serving.
`quality_passed=None` (never gated) is grandfathered servable.

## Data honesty

- **Corpus, dev vs production.** The dev seed corpus is synthetic:
  the 26-writeup golden set (25 active), seeded from
  `docs/golden/corpus.json` — a benchmark corpus, not ingested
  disclosures. Recall@10 0.9300 (18 Nov 2026) is measured on that
  corpus and is kept as a regression fixture only. The production
  corpus is real: 507 HackerOne writeups, 507/507 embeddings, as
  of 19 Nov 2026, with recall@10 0.9048 measured on it the same
  day (21 queries, pre-test 1.00, mid-test 0.714; p50 46.89 ms,
  p95 78.45 ms).
- **CVE-2021-44228 lists CWE-917 + CWE-918** in `cve_cache`
  because the two fixture writeups claim different CWEs for it
  (union). That is a synthetic-fixture claim, not NVD's canonical
  CWE. CVE-2024-12345 is a synthetic ID (KEV false).
- **Stack-match 0.7 band:** the implemented reading is 0.7
  whenever the query carries no version (there is no OSV
  affected-range data to establish a version range); the
  range-based reading is not validated by the golden set.
- **`/v1/status` `error_rate` is `null`:** there is no
  poll-attempt counter yet, so no number is invented.
- **Bounty/severity are three-tier** (platform-verified /
  author-claimed unverified / null shown as "—"); never estimated.

## Open items (none yet where stated)

- Takedowns received: none yet. DMCA notices: none yet.
  Retractions served: none yet (the retracted row in the golden
  corpus is a fixture, never served).
- DMCA agent email: not yet set — no takedown contact address has
  been published. Until the operator provides one, send takedown
  requests via a GitHub issue on this repository titled "Takedown
  request" (see `docs/policies/takedown.md`).
- Poller 7-day unattended run: none yet. The window started
  19 Nov 2026 02:49 UTC and ends around 26 Nov 2026 — see
  `docs/runbooks/dod-checklist.md`.
- Production LLM judge: none wired. Exploit / credential-use /
  state-changing actions require a judge pass AND recorded human
  approval.
- Production deployment: live since 19 Nov 2026 on the operator
  box under supervisord (API port 10004, MCP port 10005, worker
  polling every 15 minutes). `deploy/supervisord-eunoia.conf` is
  the supervisord unit installed there; `docker-compose.yml` was
  never run on a Docker host.
- Harness lookups are unmetered by design: the harness is a peer
  of the MCP server, not a client — it calls the search engine
  directly with the same parameters the MCP tool uses (limit 5/3,
  pre_test/mid_test, hybrid), bypassing auth tiers and rate limits.
  Do not point the harness at a shared registry without adding
  metering.
- stdio-mode API keys: prefer the `EUNOIA_API_KEY` environment
  variable. A key passed with `--api-key` on the command line is
  visible to other local processes in the process list.
- `run_loop` with no session opens its own session from the
  default settings (the dev database) — the same convention as
  `search()`. Pass an explicit session for any other database.
