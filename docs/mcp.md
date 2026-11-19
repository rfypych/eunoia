# MCP: connect an agent to Eunoia

Eunoia's MCP server is hosted at `http://129.150.57.82:10005/mcp`
(Streamable HTTP, stateless, `POST /mcp`). It exposes 6 read-only
tools — `search_writeups`, `get_writeup`, `get_writeup_skill`,
`list_vuln_classes`, `list_programs`, `check_freshness` — plus 2
resource templates and 1 prompt (`learn-from-writeup`). No key is
needed for keyword search; semantic and hybrid search need an API
key. The server never probes or tests a target: it only returns
past public writeups, and every result must only be used with
explicit in-scope permission.

## Connect, the easy way

From a checkout, run `eunoia setup`. It detects Claude Code, Codex
and Cursor, shows the config change, asks before writing it, and
backs up any config it replaces. `eunoia doctor` then checks the
hosted API and MCP server with no local database.

## Connect by hand

Copy one of the ready-made configs from this repo, or use the root
[mcp.json](../mcp.json) (Claude Code / generic `mcpServers` format):

- Claude Code — project file `clients/claude-code/.mcp.json`
  (copy to `.mcp.json` in your project, or merge the entry into
  `~/.claude.json`). The entry needs `"type": "http"` next to
  `"url"`; without it Claude Code treats the entry as a stdio
  command and fails.
- Codex — `clients/codex/config.toml` (merge into
  `~/.codex/config.toml`): `[mcp_servers.eunoia]` + `url`.
- Cursor — `clients/cursor/mcp.json` (merge into
  `~/.cursor/mcp.json`): `mcpServers` + plain `url`.

Local stdio mode also works, with no hosted server involved:
`python -m eunoia.mcp_server` (anonymous tier unless
`EUNOIA_API_KEY` is set).

## Claude Code plugin

`plugins/claude-code/` is a Claude Code plugin: its manifest
`.claude-plugin/plugin.json` declares `mcpServers: "./.mcp.json"`,
and `.mcp.json` carries the hosted entry. The manifest shape
follows the official Claude Code plugin manifest reference
(checked 2026-11-19). The plugin files have not been validated
inside Claude Code itself — no Claude Code session was available
here — so treat the plugin as provided, not proven, until someone
installs it in Claude Code and runs `tools/list` through it.

## Registry status: not submitted

The server is **not submitted** to the Official MCP Registry.
Checked live 2026-11-19: a search for `io.github.rfypych`
returned 0 servers and a direct lookup of
`io.github.rfypych/eunoia` returned 404. It is not listed and not
registered anywhere; do not claim otherwise.

[server.json](../server.json) at the repo root is ready for
submission. It follows the official registry schema
(`2025-12-11`, read 2026-11-19): name `io.github.rfypych/eunoia`,
description under 100 chars, exact version matching
`pyproject.toml`, and a `remotes` entry of type `streamable-http`
pointing at the hosted server. It has no `packages` entry on
purpose: the `eunoia-agents` package is not on PyPI yet, and the
registry rejects a package entry it cannot find at publish time.
Add the PyPI package entry after the first PyPI release.

Submission is blocked on the operator's identity decision:
publishing under the `io.github.rfypych` namespace needs a GitHub
login as `rfypych` (or a GitHub Actions OIDC run from this repo).
When that decision is made, validate then publish with the
official publisher CLI:

```bash
mcp-publisher validate   # checks ./server.json against the registry
mcp-publisher login github
mcp-publisher publish
```

## Verification (2026-11-19)

Verified with a real MCP client — the official Python MCP SDK
client (`mcp` 2.3.0), `streamable_http_client` + `ClientSession`,
no raw HTTP, no manual steps:

```bash
python scripts/verify_mcp_client.py
```

Result: `initialize` succeeded, `tools/list` returned exactly the
6 tools above, and `tools/call search_writeups` with query `CSRF`
returned a real writeup (`hackerone.com/reports/3882740`, medium,
CWE-352). Re-run that script to re-check; it exits non-zero if the
tool list changes or the search returns nothing.
