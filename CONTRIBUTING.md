# Contributing to Eunoia

Eunoia is an external brain for autonomous pentesting AI agents:
a metadata-plus-link index of public, authorized bug-bounty
writeups, queried over REST and a read-only MCP server. It is not
a scanner, not a payload library, and it never executes exploits.

## Setup

From a clean checkout, one command sets up the development
environment (Python 3.12 virtualenv, Postgres 16 + pgvector,
migrations, seed data):

```bash
bash scripts/setup_dev.sh
.venv/bin/python -m pytest -q
```

`setup_dev.sh` is idempotent and safe to re-run. Tests run against
a dedicated `eunoia_test` database, never the dev database and
never production.

## Workflow

- Work on a branch from `main`, one task per branch, one commit
  per task where practical.
- Add or update tests with the change, and keep the
  full suite green (`pytest -q`).
- Update the docs with the code: if behaviour, an endpoint, or a
  config changes, the matching doc changes in the same commit.
- Keep changes small and reviewable. A reviewer checks the work
  against the task brief before it merges.

## Rules that are not negotiable

- No payloads against live targets, no credentials or secrets in
  commits, fixtures, or docs.
- No real personal data in fixtures or tests; use clearly
  synthetic values.
- The registry indexes metadata and links only, never full-text
  mirrors of writeups. Every served record must pass the serving
  gate (`active`/`updated` status and the quality gate); retracted
  and takedown records are never served.
- Do not invent numbers. A measurement is reported with its date,
  corpus, and method, or it is not reported at all.

## Releases

Versioning and release notes live in `CHANGELOG.md`. A release is
a tagged commit with a changelog entry; see
`docs/runbooks/dod-checklist.md` for the Definition of Done that
a release must meet.

## Licensing

Contributions are licensed under the MIT License, the same as the
project (`LICENSE`). By submitting a change you agree to license
your contribution under those terms.
