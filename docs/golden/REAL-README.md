# Real golden set — production corpus (NOT synthetic)

Built 2026-11-19 from the live production rows on the 0xrphy-box
(API http://129.150.57.82:10004, Postgres DB `eunoia`).

- `real-queries.json` — 20 queries (12 pre-test, 8 mid-test), same
  schema as `queries.json` (`id`, `mode`, `tech`, `version`,
  `vuln_class`, `cwe`, `cve`, `evidence_pattern`,
  `expected_writeup_ids`, `notes`).
- `real-expected.json` — the `query_id -> expected ids` mapping, kept
  in agreement with `real-queries.json`.

Corpus at build time: 50 writeups, all `active`, 45 servable
(`quality_passed=true`), 5 quarantined (`quality_passed=false`,
never served), 50/50 embeddings. Every expected id was verified
against the actual production rows: the id exists, is servable,
and genuinely matches the query (same class/CWE/CVE, or the tech
word / evidence phrase in its title/excerpt).

Deliberate non-queries (documented, not scored):

- `tech: wordpress` + `vuln_class: XSS` returns nothing on this
  corpus: no servable XSS row matches tech `wordpress` — the DOM-XSS
  row on `playground.wordpress.net` is blocked by the stack-match
  word-boundary lookbehind (`(?<![\w.])`), which is by-design
  behaviour, not a miss. `rq03` covers the two wordpress rows that
  do match.
- No Java/Spring pre-test query: the production corpus holds zero
  Spring/Tomcat/Log4j writeups, so a Spring pre-test query correctly
  returns nothing. That is a corpus-coverage fact, not a recall
  signal, and is not scored here.

## Rebuild as the corpus grows

This set is a snapshot of the 50-row corpus. As ingestion adds
writeups, expected lists go stale (a new matching row is not in the
list, and recall is understated). Rebuild it from a fresh production
dump (read-only SELECTs), re-verify every expected id, and commit the
new files. Never run `scripts/measure_recall.py` or
`seed_golden_corpus` against production — those seed the synthetic
corpus. Real-corpus measurement is read-only: search calls only, see
the throwaway script used for the first measurement (kept on the box
at `/home/user/measure_real_recall.py`, not in this repo).

No invented pass threshold: recall@10 and latencies are reported as
measured; the pass bar is decided after measurement.
