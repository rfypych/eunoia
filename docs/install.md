# Install

## The working install (today)

From a checkout of the repo:

```bash
git clone https://github.com/rfypych/eunoia
cd eunoia
pip install .
eunoia setup
eunoia doctor
```

`pip install .` installs only the `eunoia` CLI, which uses the
standard library only — no heavy dependencies. Cold-cache install
in a fresh virtual environment, measured 2026-11-19: 4 s, 16 MB
venv. `eunoia setup` detects Claude Code, Codex and Cursor, shows
the config change, asks before writing it, and backs up any config
it replaces. `eunoia doctor` checks the hosted API and MCP server
with no local database. See [CLI](cli.md) for the commands.

## PyPI status: not published yet

The single PyPI command will be:

```bash
pipx install eunoia-agents
```

That command does **not** work yet: the package is not on PyPI.
The name `eunoia-agents` is free there (checked 2026-11-19; the
name `eunoia` is taken by another project). The first release is
blocked on the operator publishing the package. Until then, the
checkout install above is the working path.

## Server and embedding extras

The checkout install gives you the client only. The server
dependencies are the optional `server` extra, and the embedding
model is the separate `embed` extra (which pulls torch):

```bash
pip install ".[server]"
pip install "eunoia-agents[embed]"
```

Cold-cache `pip install ".[dev,server]"`, measured 2026-11-19:
65 s, 121 MB venv, no torch installed.

## Development setup (one command)

From a clean checkout:

```bash
bash scripts/setup_dev.sh
.venv/bin/python -m pytest -q
```

`setup_dev.sh` is idempotent and safe to re-run. It creates the
`.venv` (Python 3.12) and installs the package, brings up
Postgres 16 + pgvector (Docker Compose with
`pgvector/pgvector:pg16` when Docker is available, otherwise the
local Postgres 16 cluster, rebuilding pgvector from
`~/pgvector-build` when it is older than 0.7.0), creates the dev
(`eunoia`) and test (`eunoia_test`) databases, runs migrations on
both, and seeds the dev database.

Tests run against the dedicated `eunoia_test` database, never the
dev database and never production. If the test database is
missing, the suite fails with a message pointing at
`scripts/setup_test_db.sh` — see [Troubleshooting](troubleshooting.md).
