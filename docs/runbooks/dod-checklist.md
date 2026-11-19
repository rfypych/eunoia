# Eunoia MVP — Definition of Done checklist (spec §7.4)

Measured 18 Nov 2026. Method: the golden corpus (26 writeups, 25
active, 6 CVEs) seeded in the test database (`eunoia_test`), measured
with `scripts/measure_recall.py` and lab runs against the reference
harness with stub probes (behaviours also covered by
`tests/test_harness.py`, `tests/test_golden.py`, `tests/test_dod.py`).
Every checked item cites measured numbers, not assertions. Anything
unmeasured stays `[]` with the reason.

- [ ] 1. Poller ran 7 days unattended; every disclosed Java/Spring
  report indexed within 1h of publication; `last_successful_poll` /
  lag visible in `/status`.
  Reason: the poller has never run 7 days unattended. The mechanism
  exists (`src/eunoia/worker.py` `run_poll_cycle`, `scripts/worker.py`,
  `deploy/supervisord-eunoia.conf`, 15-minute loop + daily KEV sync)
  and `/v1/status` exposes `last_success_at` / `lag_seconds` /
  `blocked`, but no deployment has run it yet, so there is no
  7-day window to measure. To meet: deploy the poll loop, wait 7
  days, then verify `last_success_at` advances every cycle and the
  lag between a disclosed report's publication and its index time
  is <= 1h for every Java/Spring report in the window.
- [x] 2. Every CVE in the MVP writeups has `cvss_score`, `cwe_ids`
  and a KEV flag in `cve_cache`; cache enrichment < 1s.
  Evidence: 6/6 CVEs in the golden corpus have complete cache rows
  (18 Nov 2026, test DB): CVE-2020-1938 cvss 9.8, CWE-22, KEV true;
  CVE-2021-44228 cvss 10.0, CWE-917 + CWE-918, KEV true;
  CVE-2021-45046 cvss 9.0, CWE-917, KEV false;
  CVE-2022-22963 cvss 9.8, CWE-917, KEV true;
  CVE-2022-22965 cvss 9.8, CWE-917, KEV true;
  CVE-2024-12345 cvss 9.8, CWE-78, KEV false. Cache-hit
  `enrich_cve("CVE-2021-44228")` measured 0.1 ms (target < 1s),
  `stale=False`. Test:
  `tests/test_golden.py::test_every_cve_in_corpus_has_complete_cve_cache_row`.
  Note: CVE-2021-44228 lists CWE-917 + CWE-918 because the two
  fixture writeups claim different CWEs for it (union); this is a
  synthetic-fixture claim, not NVD's canonical CWE for the CVE.
- [x] 3. Zero duplicate canonical URLs / external ids; one
  HackerOne+NVD vulnerability = one search result.
  Evidence: duplicate query on the seeded test DB, 18 Nov 2026:
  duplicate `canonical_url` 0, duplicate `url_hash` 0, duplicate
  `external_id` 0 (26 writeups). Mirror merge is proven by tests:
  a HackerOne report and its Medium mirror merge into one writeup
  via `external_id` (`tests/test_dedup.py`, `tests/test_hackerone.py`,
  `tests/test_wiring.py`).
- [x] 4. Pre-test < 5s, mid-test < 3s, measured on the reference
  harness.
  Evidence: `scripts/measure_recall.py`, 18 Nov 2026 — search
  latency (all queries) p50 93.62 ms, p95 201.13 ms; pre-test p50
  89.48 ms, p95 211.21 ms (target < 5000 ms); mid-test p50 96.66 ms,
  p95 169.82 ms (target < 3000 ms). Reference-harness wall time
  288–312 ms per run (spring-boot 3.2.0: 288.64 ms; tomcat 9.0.31:
  312.48 ms; log4j 2.14.1: 303.16 ms). The search p50/p95 are the
  lookup latencies the targets apply to; harness wall time is
  dominated by the probe stub + lookups, not the search engine.
- [x] 5. Golden-set recall@10 measured and recorded.
  Evidence: `scripts/measure_recall.py`, 18 Nov 2026 — recall@10
  0.9300 over 50 queries (39 pre-test, 11 mid-test) against the
  25-active-writeup corpus; pre-test 0.9487, mid-test 0.8636; 4
  misses: q34, q37, q41, q42. No pass bar is asserted: the number
  is recorded as measured. Caveat: this is a 25-row synthetic
  corpus, not a launch number — re-measure after real ingestion
  before any pass bar is set (Task 15 minor). Test:
  `tests/test_golden.py::test_golden_set_has_50_queries`.
- [x] 6. The loop runs end-to-end in the lab; Scope Gate blocks
  out-of-scope targets including via redirect; Lookup #2 fires
  after 3 failed probes and returns <= 3 writeups; Prove rejects
  at least one unreproducible claim.
  Evidence: lab runs 18 Nov 2026 (test DB, golden corpus, stub
  probes, target `https://app.lab.internal`, scope
  `app.lab.internal`):
  - Run A (`probes_fail=3`): status `completed`, 6/6 hypotheses
    confirmed after Lookup #2; 7 Lookup #2 calls, results per call
    [2, 0, 0, 2, 0, 0, 1] — every call <= 3.
  - Run B (probe never signals): 6/6 hypotheses debunked, 0
    confirmed, 0 findings — no unproven claim is reported.
    At run level the rejection surfaces as `debunked` (the claim
    is removed from findings entirely); Prove's `unverified`
    verdict itself is unit-verified in
    `tests/test_harness.py::test_prove_unverified_without_reproduction_steps`
    (`prove_candidate` with no reproduction steps -> `unverified`).
  - Run C (target `https://example.com`, scope `lab.internal`):
    `ScopeBlocked` raised before any lookup.
  - Run D (first probe redirects to `https://evil.example/x`):
    1 `redirect_blocked` audit event; the redirect is not
    followed, the observation is treated as no-signal.
  Tests: `test_scope_gate_blocks_out_of_scope_target`,
  `test_lookup2_triggered_after_3_failed_probes`,
  `test_redirect_outside_allowlist_blocked_in_run`.
- [x] 7. Token budget obeyed in the lab run (retrieval <= 20k/run,
  limits 5/3, compaction at 65% or the run finishing before the
  threshold and recorded).
  Evidence: Run A coverage, 18 Nov 2026 — `retrieval_tokens`
  2,200 (cap 20,000); `budget_action` `"ok"`;
  `window_used_pct` 1.1% (compaction line 65%); Lookup #1 limit 5,
  Lookup #2 limit 3 per call. The run finished before the
  threshold and the report records it (`budget_action` +
  `window_used_pct` in `coverage`). Test:
  `tests/test_harness.py::test_run_report_records_budget_before_threshold`.
  Known limitation (Task 14 minor, recorded not hidden): only
  retrieval tokens are charged to the budget, so the prune (50%)
  / compact (65%) hooks cannot fire in a real run — window-level
  accounting for scratchpad/state tokens belongs to the planner.
- [x] 8. No verbatim payload for a live target in any skill or
  excerpt (sample check); every skill carries an authorization
  warning; the audit log traces one full lab run
  query -> hypothesis -> probe -> evidence -> report.
  Evidence: 18 Nov 2026, full corpus (stronger than a sample) —
  25/25 servable skills carry the authorization warning;
  `scan_secrets` over all 25 skill texts + all 25 excerpts: 0
  findings. Run A audit trail, in order: `scope_gate_passed` ->
  `recon_done` -> `lookup1_done` -> `lookup2_done` -> `prove_done`
  -> `report_done` (query -> hypothesis -> probe -> evidence ->
  report). Tests: `test_skill_has_auth_warning_and_no_payload`,
  `test_secret_scan_blocks_token_in_excerpt`.
- [x] 9. Zero High/Critical findings claimed without reproduction
  evidence.
  Evidence: Run A — 6 confirmed findings, each backed by a
  signalling probe observation plus minimal reproduction steps
  (`prove_candidate` returns `confirmed` only with both); Run B —
  0 findings from 6 unproven hypotheses. Mechanism, not just
  this run: a finding reaches `confirmed` only through
  `prove_candidate` with signal + steps, and material findings
  require human review
  (`test_report_requires_human_review_for_material_findings`).
  Note: the lab runs use stub probes against a synthetic corpus —
  "confirmed" here means confirmed against the stub, not against
  a live target.
- [x] 10. OpenAPI, llms.txt, status page and transparency note live.
  Evidence: OpenAPI 3.x served at `/api/v1/openapi.json`
  (`tests/test_api.py::test_openapi_at_api_v1_path`); llms.txt
  served at `GET /llms.txt`
  (`tests/test_api.py::test_llms_txt_served`); status page at
  `GET /v1/status` with `last_success_at`, `lag_seconds`,
  `blocked` / `blocked_reason`
  (`tests/test_api.py::test_status_public_and_surfaces_blocked`);
  transparency note: `docs/transparency.md` (this repo). Values
  that do not exist yet are stated there as "none yet" rather
  than invented.

## Known gaps / launch blockers (not hidden)

- DoD 1 is unmet: no 7-day unattended poller run has happened yet.
- DMCA agent email is a placeholder (`dmca@eunoia.example`) — must
  be replaced with a real operator contact before public launch.
- No production deployment exists yet: `deploy/supervisord-eunoia.conf`
  is an example config, not installed anywhere; `docker-compose.yml`
  was never run on a Docker host.
- Recall 0.9300 is a synthetic-corpus measurement (Task 15 minor);
  re-measure after real ingestion before setting a pass bar.
- No production LLM judge is wired (spec §9 Q4, `JUDGE_Q4_DEBT` in
  `src/eunoia/safety/approvals.py`): exploit / credential-use /
  state-changing actions require a judge pass AND recorded human
  approval, and the judge is a configured component, not a
  production model.
- The 65% compaction / 50% prune hooks cannot fire in real runs
  (DoD 7 note above) — window-level token accounting belongs to
  the planner.
- `error_rate` in `/v1/status` is honestly `null`: there is no
  poll-attempt counter yet.
