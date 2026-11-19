# Golden set — recall@10 + latency measurement (Task 15, spec §8)

## Files

- `corpus.json` — 26 writeups (24 servable + 1 retracted + 1
  non-English) with deterministic UUIDv7 ids, so the same `w_...`
  api ids exist in the dev DB and the test DB. Synthetic fixtures
  modelled on real Java/Spring writeups + CVEs (Log4Shell,
  Spring4Shell, Ghostcat); a benchmark corpus, not ingested
  disclosures. Seed it with `seed_golden_corpus()` (`eunoia.golden`)
  or `python scripts/measure_recall.py` (dev DB, idempotent).
- `queries.json` — 50 queries (39 pre-test, 11 mid-test), each with
  `expected_writeup_ids` naming real corpus rows.
- `expected.json` — the `query_id -> expected ids` mapping; must agree
  with `queries.json` (tested).

## First measurement (2026-11-18, this repo, 25 active writeups)

Measured with `scripts/measure_recall.py` (real `all-MiniLM-L6-v2`
model, dev DB) and reproduced exactly with the keyword stub encoder
in `tests/test_golden.py` — recall is identical under both encoders;
only latencies differ.

| | recall@10 | p50 | p95 | target |
|---|---|---|---|---|
| all (50 queries) | **0.9300** | 89 ms | 193 ms | — |
| pre-test (39) | 0.9487 | 88 ms | 209 ms | <5000 ms |
| mid-test (11) | 0.8636 | 102 ms | 147 ms | <3000 ms |

Harness runs (reference loop, lab-only stub probes): 306–518 ms wall
per run, 6 queries/run (1 Lookup #1 + 5 Lookup #2), 1600–1800
retrieval tokens — far under the 20,000/run cap.

## The 4 misses (honest signal, not bugs)

- `q34` (pre-test, endpoint `user api` -> IDOR writeup) and `q37`
  (pre-test, endpoint `file download` -> path-traversal writeup):
  both expected rows are medium severity, no bounty, no KEV. In a
  broad pre-test query the evidence ranking buries them under
  KEV/verified rows; they rank 11th+. The endpoint pattern only adds
  BM25 terms — it does not boost the target in ranking.
- `q41` (mid-test, `remote code execution wordpress plugin` ->
  WordPress RCE): cross-stack technique match. Stack 0.0 costs the
  full 0.30 stack weight in mid-test ranking, and technique
  similarity alone cannot compensate against strong same-stack rows.
- `q42` (mid-test, stored XSS -> both Spring stacks): the
  Spring Framework XSS row (family stack 0.2) falls just outside
  top-10 behind same-stack rows.

## Rules

- **No invented pass threshold.** The numbers above are reported
  as measured; the pass bar is decided after this first measurement.
- **Re-measure on every embedding/ranking change** before shipping
  it: `python scripts/measure_recall.py`.
- **0.7 stack-match band (Task 9 minor).** The ranking implements
  0.7 whenever the query carries no version ("same product, version
  not exactly known") — NOT the spec's range-based reading ("same
  product, version in affected range"), because MVP has no OSV data
  to establish affected ranges. The golden set validates the
  implemented reading (`test_stack_match_07_band_reading`); the
  range-based reading is untestable in MVP. Versioned queries score
  1.0 on an exact version match (the classifier fills the CPE
  version slot from the version next to the technology mention) and
  0.4 when the writeup names no version.
