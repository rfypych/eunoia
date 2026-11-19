# Eunoia runbook — deployment schedules and recovery

The schedules below are real mechanisms, not prose:
`src/eunoia/worker.py` (`run_poll_cycle`, `run_kev_sync_once`),
`scripts/worker.py` (thin CLI), `deploy/supervisord-eunoia.conf`
(supervisord unit + the cron line for KEV sync). What
deployment still has to do is install those units and point
`DATABASE_URL` at the deployment Postgres — nothing in this repo
runs them on its own.

Fresh database, in order: `bash scripts/setup_dev_db.sh` (creates
the `eunoia` role + database; test DB equivalent is
`scripts/setup_test_db.sh`), `PYTHONPATH=src .venv/bin/alembic
upgrade head`, then `.venv/bin/python scripts/seed_sources.py`
(seeds the `sources` table — the worker poller fails with
"source 'hackerone' not found" without it).

## Schedules

### 1. Poll loop — every 15 minutes

```sh
.venv/bin/python scripts/worker.py poll-loop --interval-minutes 15
```

One cycle calls `poll_hackerone()` (no auth needed — the Hacktivity
REST API works without a token; see
`docs/probes/hackerone-auth-2026-11-18.md`), then drains the jobs
queue: repeatedly `claim_next_job(session)`
and `process_job(session, job.id, handler)` until no job is due.
`dispatch_job` routes by `kind`:

- `hackerone_discovery` / `discovery` → the discovery worker, which
  upserts the writeup and then runs the enrichment pipeline
  (classify → quality gate → enrich CVEs → embed) inline. The
  quality gate's URL check defaults to the production HEAD/GET
  check (`_default_url_checker`); the worker passes no stub.
- `nvd_refresh` → `handle_nvd_refresh_job`, which re-fetches one CVE
  into `cve_cache`. These jobs are queued by `enrich_cve` whenever an
  NVD fetch degrades; without a worker loop consuming them, refresh
  jobs accumulate unprocessed and stale cache rows never refresh.
  The drain passes NVD client/limiter only to refresh jobs —
  `handle_nvd_refresh_job` rejects unknown kwargs, so discovery
  kwargs (`model`, `url_checker`) are never forwarded to it.

`process_job` marks success `done`, failure `pending` with back-off
1m → 1h → 1d, dead-lettered after 5 attempts. A discovery job never
fails because of the pipeline: a pipeline step that raises is
recorded in the writeup event's `pipeline_errors` detail and the job
still completes. A job that raises inside `process_job` is counted
as failed by the cycle and the drain continues with the next job.

`scripts/worker.py poll-loop --once` runs a single cycle (for cron
instead of supervisord); `drain-once` drains due jobs without
polling.

### 2. KEV sync — daily

```sh
.venv/bin/python scripts/worker.py kev-sync
```

Calls `sync_kev(session)` (CISA Known Exploited Vulnerabilities
catalog, CC0). It only flips the `kev` flag / `kev_date_added` on
`cve_cache` rows and never overwrites NVD data. Idempotent — a second
sync with the same catalog changes nothing.

### 3. API keys — operator action, no HTTP route

```sh
DATABASE_URL=postgresql://eunoia@localhost/eunoia \
  .venv/bin/python scripts/create_api_key.py --owner alice
```

Prints the plaintext key once (it is stored only as a SHA-256 hash
and can never be recovered). There is deliberately no HTTP admin
route for provisioning.

## Harness notes

- **The harness is a peer of the MCP server, not a client.**
  `run_loop` calls the search engine directly with the same
  parameters the MCP `search_writeups` tool uses (limit 5/3,
  pre_test/mid_test, hybrid), bypassing auth tiers and rate limits.
  Its lookups are intentionally unmetered. Do not point the
  harness at a shared registry without adding metering.
- **`run_loop` with no session opens its own from the default
  settings (the dev database)** — the same convention as
  `search()`. Pass an explicit session for any other database.
- **Only retrieval tokens are charged to the budget**, so the
  prune (50%) / compact (65%) hooks cannot fire in a real run;
  window-level token accounting for scratchpad/state belongs to
  the planner. A run records that it finished before the
  threshold (`budget_action` + `window_used_pct` in `coverage`).

## Recovery notes

- **Postgres does NOT auto-start after a VM reboot.** Start it with:

  ```sh
  sudo pg_ctlcluster 16 main start
  ```

- **pgvector ≥ 0.7.0 is required on the server** (the `halfvec`
  type used by the `embeddings` table does not exist in 0.6.0).
  On this VM it was built from source into `~/pgvector-build`; if a
  reboot or reinstall wipes it, rebuild from that directory and run
  `ALTER EXTENSION vector UPDATE` in both the `eunoia` and
  `eunoia_test` databases. A migration fails with
  `type "halfvec" does not exist` when the server extension is too old.

- **Test database:** `bash scripts/setup_test_db.sh` (idempotent)
  recreates the `eunoia_test` database and extensions. Test failures
  mentioning a missing `eunoia_test` database point at that script.

- **httpx + this VM's environment:** a plain `httpx.Client()`
  crashes on the bracketed IPv6 entries in `NO_PROXY`
  (`[::1]` → `Invalid port: ':1]'`). Always build clients via the
  `trust_env=False` helpers (`_default_client()` in the poller,
  `default_http_client()` in `ingestion/nvd.py`).

- **Embedding model:** `all-MiniLM-L6-v2` via `sentence-transformers`
  (full CUDA torch bundle, ~2 GB of wheels). The model is loaded once
  per process (`embed.get_model`) and reused; never construct a new
  model per job.
