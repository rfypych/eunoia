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

### Pending operator decisions

The following are not code changes and cannot be completed by a
contributor; they need a decision from the project operator:

- DMCA agent email: not yet set. No takedown contact address has
  been published; see `docs/policies/takedown.md` and
  `docs/transparency.md` for the current status.
- Domain and trademark for the Eunoia name: unchecked.
- Public package name and publishing identity for the installable
  client: unchecked.

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
