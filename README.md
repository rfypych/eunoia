# Eunoia

External brain for autonomous pentesting AI agents. "Stack in, attack plan out."

- Registry: metadata-plus-link index of public, authorized bug-bounty writeups + CVE enrichment.
- Query primitive: `rencana(stack, konteks) -> hipotesis serangan terurut berdasarkan bukti`.
- Access: REST v1 + read-only MCP server (5 tools). No scanner, no payload library, no exploit execution.

Spec: `~/workspace/research_notes/final-product-ready-to-build.md`
Plan: `~/workspace/plans/2026-11-18-eunoia-mvp.md`

## Test database

Tests run against a dedicated `eunoia_test` database, never the dev database.
On a fresh checkout, create it once with:

```bash
bash scripts/setup_test_db.sh
```

The script is idempotent and safe to re-run. If the test database is missing,
`pytest tests/test_models.py` fails with a message pointing at that script.
