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
