# Changelog

All notable changes to this project are documented here. The format
is based on Keep a Changelog, and this project adheres to Semantic
Versioning.

## [Unreleased]

### Added

- Reproducible development setup: one-command `scripts/setup_dev.sh`
  (Postgres 16 + pgvector, migrations, seed data) and GitHub Actions
  CI running the full suite from a clean checkout.
- Legal and release-basis files: MIT `LICENSE`, `SECURITY.md`,
  `CONTRIBUTING.md`, and this changelog.
- One-command hosted install: package `eunoia-agents` with the `eunoia`
  CLI (`setup`, `doctor`, `update`). `eunoia setup` detects Claude
  Code, Codex and Cursor, shows the planned config change, asks before
  writing it, and backs up replaced configs. `eunoia doctor` checks the
  hosted API and MCP server with no local database. The package is not
  on PyPI yet (the name `eunoia` is taken there); until the first PyPI
  release, install from a checkout with `pip install .`.
- MCP discoverability: `mcp.json`, `server.json` (Official MCP
  Registry format, namespace `io.github.rfypych/eunoia`), per-client
  configs for Claude Code, Codex and Cursor under `clients/`, a Claude
  Code plugin under `plugins/claude-code/`, and `docs/mcp.md`. The
  server has not been submitted to the registry yet; submission needs
  the operator's identity decision. Verified 2026-11-19 with the
  official Python MCP SDK client: `tools/list` returns the 6 tools and
  `search_writeups` returns real results.
- Lightweight CLI install (fix T5): the base package has no
  dependencies — the CLI is stdlib-only. Server dependencies moved to
  the `server` extra and the embedding model to the `embed` extra
  (which pulls torch). Cold-cache install measured 2026-11-19: base
  `pip install .` 4 s / 16 MB venv (was 24 min / 5.8 GB with torch as
  a base dependency); `.[dev,server]` cold 65 s / 121 MB, no torch.
  The README now leads with the checkout install that works today;
  `pipx install eunoia-agents` is documented as the command after the
  first PyPI release, which is blocked on the branch being pushed (T2)
  and on publishing. `eunoia update` now distinguishes "not published
  on PyPI yet" (404) from "could not reach PyPI" (network/5xx).
  `eunoia setup` keeps the first backup at `.bak` and timestamps
  later ones instead of overwriting it. `scripts/setup_dev.sh`
  reinstalls the editable package on every re-run so the `eunoia`
  command is present in the dev venv.
- Website / demo live at the API root (T6): a search box that calls
  the live `/v1/search`, a CSRF search on load, the live corpus
  size from `/v1/status`, and links to the API docs, `llms.txt`, MCP,
  and GitHub. The page says the `eunoia-agents` package is not on
  PyPI yet and never claims 500 writeups.
- Corpus grown to 507 real HackerOne writeups (was 50): a backfill
  script (`scripts/backfill_hackerone.py`) walks Hacktivity pages
  newest-first through the normal discovery pipeline; the Hacktivity
  API returns 50 items on page 1 and 10 per page after that, so 47
  pages cover 500 items. Unclassified rows fell from 20 of 50 to 45
  of 507 (8.9%) through three changes: new CWE-to-class mappings
  for CWEs NVD actually returns (CWE-261/297/305 → Auth Bypass,
  CWE-312 → Info Disclosure, CWE-667 → DoS, CWE-1021 →
  Clickjacking), an explicit technique-name text fallback for rows
  with no CWE (measured: it classifies 96 of the 145 rows that had
  no CWE), and an NVD re-apply step (`apply_cached_nvd`) that
  backfills CVSS/severity/class onto rows whose CVE NVD had not
  published yet at ingest time. Recall re-measured with the same
  method on the 507-writeup corpus: recall@10 0.9048 (pre-test
  1.00, mid-test 0.714), p50 46.89 ms, p95 78.45 ms — see
  `docs/reports/corpus-500.md` for the misses, the scope finding
  (0 of the 100 newest disclosed reports mention Java/Spring), and
  the verified CVE-2026-110288. The recall query set
  (`docs/golden/real-queries-500.json`, 21 queries) is built by
  `scripts/build_real_queries.py` and validated before measuring;
  expected ids are database UUIDs, so the set is rebuilt on the
  database being measured.
- Installable skills (T9): `eunoia skills install` writes the
  registry skill (`writeup-registry`, shipped as package data) plus
  one per-class skill per real vuln class into each detected agent's
  skills directory (Claude Code `~/.claude/skills`, Codex
  `~/.agents/skills`, Cursor `~/.cursor/skills`); per-class skills
  are fetched live from the new `GET /v1/vuln-classes/{class}/skill.md`
  endpoint, `unclassified` is never installed, and the install shows
  the plan, asks before writing, and backs up replaced skills.
  Installed skills work over the REST API alone — no MCP server and
  no local database are needed to use them; the per-writeup skill is
  available over REST and over MCP as two transports for the same
  text. A verified pre-test (CSRF, report 3882740) and mid-test (SSRF,
  report 366638) walkthrough is in the README, both verified live
  2026-11-19.

### Pending operator decisions

The following are not code changes and cannot be completed by a
contributor; they need a decision from the project operator:

- DMCA agent email: not yet set. No takedown contact address has
  been published; see `docs/policies/takedown.md` and
  `docs/transparency.md` for the current status.
- Domain and trademark for the Eunoia name: unchecked.
- Public package name and publishing identity for the installable
  client: the name `eunoia-agents` is free on PyPI (checked
  2026-11-19), but the first PyPI release is blocked on the branch
  being pushed to GitHub (T2) and on the operator publishing it.
  Until then the T5 acceptance (one-command install from PyPI) is
  not met; the checkout install (`pip install .`) is the working
  path and is measured in the README.

## [0.1.0] - 2026-11-19

### Added

- MVP merged to `main`: FastAPI REST API (`/v1/...`) and a read-only
  MCP server with 6 tools, backed by Postgres 16 + pgvector.
- Ingestion from HackerOne Hacktivity (no auth required) with NVD
  CVE enrichment, a 5-layer dedup pipeline, a quality gate, and a
  serving gate that never serves retracted or takedown records.
- Skill generation per writeup (`SKILL.md`) and `llms.txt`.
- Lab-only reference harness (10-step loop) and a safety gate
  (scope, approvals, audit log, takedown handling).
- Golden-set recall measurement: recall@10 0.93 on the synthetic
  26-writeup corpus (18 Nov 2026); re-measured at recall@10 0.90
  on the real 50-writeup corpus on 19 Nov 2026.
- Production deployment on the operator box under supervisord:
  API on port 10004, MCP on port 10005, worker polling every
  15 minutes. Live corpus: 50 real HackerOne writeups, 50/50
  embeddings, as of 19 Nov 2026.

### Known gaps at release

- No 7-day unattended poller run yet; the 7-day window started
  19 Nov 2026 02:49 UTC and completes around 26 Nov 2026.
- No production LLM judge wired.
- DMCA agent email not yet set (see Unreleased above).
