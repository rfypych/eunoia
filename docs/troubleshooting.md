# Troubleshooting

## `eunoia doctor` fails

Run it with the exact output — it tells you which side is down:

```bash
eunoia doctor
```

- **API down:** check the live status at
  <http://129.150.57.82:10004/v1/status> from a browser. If the
  page does not load, the hosted API is down; nothing on your
  machine fixes that.
- **MCP down:** the API can be up while the MCP server is down.
  Doctor reports each separately.

## MCP client says the server entry is a command, not a URL

Claude Code needs `"type": "http"` next to the `"url"` in the
`mcpServers` entry. Without it, Claude Code treats the entry as
a stdio command and fails. The correct entry is:

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

`eunoia setup` writes this correctly. If you edited the config
by hand, add the `"type"` line. Codex and Cursor use different
formats — see [MCP](mcp.md) and [CLI](cli.md).

## Search returns at most 10 results

That is the limit, not a bug. The REST search limit is clamped
to 10 (default 5); asking for more returns 10 and the response
reports the effective limit.

## Semantic or hybrid search returns 403

Anonymous callers get keyword mode only. Semantic and hybrid
search need an API key (`MODE_REQUIRES_KEY`). Keyword search
needs no key.

## `pipx install eunoia-agents` fails with 404

The package is not on PyPI yet. Install from a checkout instead
— see [Install](install.md). The first PyPI release is blocked
on the operator publishing the package.

## Tests fail: test database missing or unreachable

```
Test database 'eunoia_test' is missing or unreachable.
Create it with: bash scripts/setup_test_db.sh
```

Run the setup script, or the one-command setup that includes it:

```bash
bash scripts/setup_dev.sh
.venv/bin/python -m pytest -q
```

Tests run against the dedicated `eunoia_test` database, never the
dev database and never production.

## Tests fail: `type "halfvec" does not exist`

The Postgres server has pgvector older than 0.7.0. The
`embeddings` table needs the `halfvec` type, which only exists in
pgvector 0.7.0 and later. Rebuild pgvector from
`~/pgvector-build` and run `ALTER EXTENSION vector UPDATE` in
both the `eunoia` and `eunoia_test` databases — or use Docker,
which `setup_dev.sh` does automatically when Docker is
available (`pgvector/pgvector:pg16`).

## Postgres does not start after a VM reboot

Postgres does not auto-start after a reboot on the development
VM. Start it with:

```bash
sudo pg_ctlcluster 16 main start
```

Then re-run `bash scripts/setup_dev.sh` (it is idempotent) to
bring the databases back up.

## `eunoia setup` did nothing on the second run

That is the expected no-op: the config is already correct.
Re-run it after changing the hosted URL or after editing the
config by hand; it shows the change, asks before writing, and
backs up what it replaces (first backup `<file>.bak`, later ones
timestamped).
