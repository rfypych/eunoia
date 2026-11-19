# CLI

The `eunoia` command wires your agent to the hosted server. It
uses only the standard library, so it works with no local
database and no server installed. Install it first — see
[Install](install.md).

```bash
eunoia --help
eunoia --version
```

## `eunoia setup`

Detects Claude Code, Codex and Cursor, shows the config change,
asks before writing it, and backs up any config it replaces (the
first backup is `<file>.bak`, later ones are timestamped).

```bash
eunoia setup
```

What it writes, per client:

| Agent | File | Entry |
| --- | --- | --- |
| Claude Code | `~/.claude.json` | `"type": "http"`, `"url": "http://129.150.57.82:10005/mcp"` |
| Codex | `~/.codex/config.toml` | `[mcp_servers.eunoia]` + `url` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` + plain `url` |

The `"type": "http"` next to the URL matters for Claude Code:
without it, Claude Code treats the entry as a stdio command and
fails. Re-running setup is a no-op when the config is already
correct.

## `eunoia doctor`

Checks the hosted API and MCP server with no local database, and
exits non-zero if either is down:

```bash
eunoia doctor
```

```text
API http://129.150.57.82:10004: OK (507 writeups active)
MCP http://129.150.57.82:10005/mcp: OK (6 tools)
search_writeups: OK
OK
```

The numbers are live: the writeup count comes from `/v1/status`
and the tool count from `tools/list`. Doctor checks the hosted
services only; it does not test a real agent session.

## `eunoia update`

Upgrades `eunoia-agents` from PyPI:

```bash
eunoia update
```

It reports honestly when the package is not published yet (PyPI
404) and fails with exit 1 when PyPI cannot be reached at all
(network error or 5xx). Until the first PyPI release, update by
pulling the checkout and re-installing:

```bash
git pull
pip install .
```

## `eunoia skills install` / `eunoia skills list`

Installs the registry skill (`writeup-registry`) plus one skill
per real vulnerability class into each detected agent's skills
directory:

```bash
eunoia skills install
eunoia skills list
```

| Agent | Skills directory |
| --- | --- |
| Claude Code | `~/.claude/skills/<name>/SKILL.md` |
| Codex | `~/.agents/skills/<name>/SKILL.md` |
| Cursor | `~/.cursor/skills/<name>/SKILL.md` |

The registry skill ships with the package; per-class skills are
fetched live from the hosted API at install time, so re-running
the install refreshes them. `unclassified` is never installed:
there is no technique to teach for a class that means "not yet
classified". The install shows the plan, asks before writing, and
backs up any skill it replaces.

Installed skills work over the REST API alone — no MCP server and
no local database are needed to use them. The per-writeup skill
is available over REST and over MCP as two transports for the
same text: `GET /v1/writeups/{id}/skill.md`, or the
`get_writeup_skill` MCP tool.
