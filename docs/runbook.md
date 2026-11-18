# Eunoia runbook — deployment schedules and recovery

This is documentation only. The schedules below are deployment wiring
(cron / systemd / a small runner process); no scheduler lives in the
codebase yet. Task 16 owns turning this into deployed units.

## Schedules deployment must provide

### 1. Poll loop — every 15 minutes

Call `poll_hackerone()` (no auth needed — Task 1 decision:
Hacktivity REST works without a token, `no_auth_ok`), then drain the
jobs queue: repeatedly `claim_next_job(session)` and run
`process_job(session, job.id, dispatch_job)` until no job is due.
`dispatch_job` routes by `kind`:

- `hackerone_discovery` / `discovery` → the discovery worker, which
  upserts the writeup and then runs the enrichment pipeline
  (classify → enrich CVEs → embed) inline.
- `nvd_refresh` → `handle_nvd_refresh_job`, which re-fetches one CVE
  into `cve_cache`. These jobs are queued by `enrich_cve` whenever an
  NVD fetch degrades; without a worker loop consuming them, refresh
  jobs accumulate unprocessed and stale cache rows never refresh.

`process_job` marks success `done`, failure `pending` with back-off
1m → 1h → 1d, dead-lettered after 5 attempts. A discovery job never
fails because of the pipeline: a pipeline step that raises is
recorded in the writeup event's `pipeline_errors` detail and the job
still completes.

### 2. KEV sync — daily

Call `sync_kev(session)` (CISA Known Exploited Vulnerabilities
catalog, CC0). It only flips the `kev` flag / `kev_date_added` on
`cve_cache` rows and never overwrites NVD data. Idempotent — a second
sync with the same catalog changes nothing.

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
