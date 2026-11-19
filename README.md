# Eunoia

External brain for autonomous pentesting AI agents. "Stack in, attack plan out."

- Registry: metadata-plus-link index of public, authorized bug-bounty writeups + CVE enrichment.
- Query primitive: `rencana(stack, konteks) -> hipotesis serangan terurut berdasarkan bukti`.
- Access: REST v1 + read-only MCP server (5 tools). No scanner, no payload library, no exploit execution.

Spec: `~/workspace/research_notes/final-product-ready-to-build.md`
Plan: `~/workspace/plans/2026-11-18-eunoia-mvp.md`

## Development setup (one command)

From a clean checkout, run:

```bash
bash scripts/setup_dev.sh
.venv/bin/python -m pytest -q
```

`setup_dev.sh` is idempotent and safe to re-run. It creates the
`.venv` (Python 3.12) and installs the package, brings up
Postgres 16 + pgvector (Docker Compose with `pgvector/pgvector:pg16`
when Docker is available, otherwise the local Postgres 16 cluster,
rebuilding pgvector from `~/pgvector-build` when it is older than
0.7.0), creates the dev (`eunoia`) and test (`eunoia_test`)
databases, runs migrations on both, and seeds the dev database.

## Test database

Tests run against a dedicated `eunoia_test` database, never the dev database.
`setup_dev.sh` creates it; the lower-level scripts
`scripts/setup_dev_db.sh` / `scripts/setup_test_db.sh` still exist for
the local-cluster path. If the test database is missing,
`pytest tests/test_models.py` fails with a message pointing at that script.
