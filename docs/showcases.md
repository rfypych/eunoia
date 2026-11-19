# Showcases

Three real cases, each run against the live API with no key, on the
live corpus of 507 active writeups. Every query below can be re-run
exactly as written; the numbers are as measured on 19 Nov 2026.
Ranks and scores move as the corpus grows (the poller adds new
disclosed reports roughly every 15 minutes), so a later re-run may
show different ranks — that is expected, and the measurement date
is part of each case.

Aggregate numbers behind these cases are in
[docs/reports/corpus-500.md](reports/corpus-500.md): recall@10
0.9048 overall on 21 queries (pre-test 1.00, mid-test 0.714),
latency p50 46.89 ms, p95 78.45 ms, 507 writeups, 45 unclassified
(8.9%).

## Showcase 1

### Target

A web app about to be tested. The tester wants the CSRF cases that
matter most before writing a test plan.

### Question

Which disclosed CSRF writeups should shape the plan?

### Steps

1. Check the corpus size (live, no key):

   ```bash
   curl -s http://129.150.57.82:10004/v1/status
   ```

   Result: 507 writeups active, source HackerOne ok, 0 consecutive
   failures.

2. Ask for CSRF (anonymous search, keyword mode, pre-test ranking):

   ```bash
   curl -s "http://129.150.57.82:10004/v1/search?q=CSRF&limit=5"
   ```

3. Read the per-class guide for the top class:

   ```bash
   curl -s http://129.150.57.82:10004/v1/vuln-classes/CSRF/skill.md
   ```

   Result: HTTP 200, 1642 bytes.

### Evidence

| Rank | Report | Severity | CWE | CVE | Score |
| --- | --- | --- | --- | --- | --- |
| 1 | [hackerone.com/reports/3882740](https://hackerone.com/reports/3882740) | medium | CWE-352 | CVE-2026-110288 | 0.6745 |
| 2 | [hackerone.com/reports/3981932](https://hackerone.com/reports/3981932) | medium | CWE-352 | CVE-2026-77168 | 0.6601 |
| 3 | [hackerone.com/reports/2999394](https://hackerone.com/reports/2999394) | medium | CWE-269 | — | 0.6044 |
| 4 | [hackerone.com/reports/2002352](https://hackerone.com/reports/2002352) | medium | CWE-352 | — | 0.5879 |
| 5 | [hackerone.com/reports/2261600](https://hackerone.com/reports/2261600) | low | CWE-352 | — | 0.5525 |

The top result, "All stored Slack and Teams credentials can be
deleted via Management Console CSRF", is the writeup whose CVE
(CVE-2026-110288) was checked against NVD and CVE.org and kept
(see [docs/reports/corpus-500.md](reports/corpus-500.md)).

### Numbers

- Pre-test recall@10: 1.00 (14 of 14 queries) on the 21-query set.
- Corpus recall@10: 0.9048, p50 46.89 ms, p95 78.45 ms.
- CSRF class: 5 servable writeups — the table above is the whole
  class, ranked.

### Limitations

- Anonymous search is keyword-only, with a limit of 10. Semantic
  and hybrid search need an API key.
- Bounty amounts on these rows are unverified (null); do not quote
  them as payouts.
- The ranking is by the corpus as it stood on 19 Nov 2026. A newer
  CSRF report can outrank these rows on a later re-run.

## Showcase 2

### Target

Mid-test: a form input looks injectable. The tester has a
suspicious candidate and wants to know whether it matches a known
blind SQL injection pattern before spending more time on it.

### Question

Does the candidate match a known blind SQL injection writeup, and
does the mid-test ranking change the answer?

### Steps

1. Search with the default (pre-test) ranking:

   ```bash
   curl -s "http://129.150.57.82:10004/v1/search?q=Blind%20SQL%20injection&limit=5"
   ```

2. Repeat with the mid-test ranking:

   ```bash
   curl -s "http://129.150.57.82:10004/v1/search?q=Blind%20SQL%20injection&lookup=mid_test&limit=5"
   ```

### Evidence

Pre-test ranking:

| Rank | Report | Severity | CWE | Score |
| --- | --- | --- | --- | --- |
| 1 | [hackerone.com/reports/4077800](https://hackerone.com/reports/4077800) | medium | CWE-78 | 0.7252 |
| 2 | [hackerone.com/reports/3896779](https://hackerone.com/reports/3896779) | high | CWE-89 | 0.7081 |
| 3 | [hackerone.com/reports/3797662](https://hackerone.com/reports/3797662) | high | CWE-89 | 0.7043 |
| 4 | [hackerone.com/reports/2830573](https://hackerone.com/reports/2830573) | critical | CWE-89 | 0.6863 |
| 5 | [hackerone.com/reports/2817658](https://hackerone.com/reports/2817658) | critical | CWE-78 | 0.6710 |

Mid-test ranking, same query:

| Rank | Report | Severity | CWE | Score |
| --- | --- | --- | --- | --- |
| 1 | [hackerone.com/reports/4077800](https://hackerone.com/reports/4077800) | medium | CWE-78 | 0.5286 |
| 2 | [hackerone.com/reports/2830573](https://hackerone.com/reports/2830573) | critical | CWE-89 | 0.5181 |
| 3 | [hackerone.com/reports/2633959](https://hackerone.com/reports/2633959) | critical | CWE-89 | 0.5105 |
| 4 | [hackerone.com/reports/2817658](https://hackerone.com/reports/2817658) | critical | CWE-78 | 0.5105 |
| 5 | [hackerone.com/reports/3896779](https://hackerone.com/reports/3896779) | high | CWE-89 | 0.5103 |

The blind SQL injection writeup
[hackerone.com/reports/3896779](https://hackerone.com/reports/3896779)
("Blind SQL injection due to request precedence issue in global
input registration") is rank 2 pre-test (0.7081) and rank 5
mid-test (0.5103): the same candidate stays in the top 5 under
both rankings, but drops three places mid-test.

### Numbers

- Mid-test recall@10: 0.714 (5 of 7 queries) on the 21-query set;
  pre-test recall@10: 1.00 (14 of 14).
- Corpus recall@10: 0.9048, p50 46.89 ms, p95 78.45 ms.

### Limitations

- Mid-test is the weak point: the two production misses were both
  2022 reports with low severity and no CVSS
  ([hackerone.com/reports/1672614](https://hackerone.com/reports/1672614),
  [hackerone.com/reports/1166073](https://hackerone.com/reports/1166073)).
  Old, low-severity rows lose to newer rows with similar technique
  similarity.
- The 0.714 mid-test recall was measured with the full search on
  the 21-query set; the anonymous search used here is keyword-only,
  so an individual mid-test query can rank differently. Checked
  live: the evidence pattern "All stored Slack" with
  `lookup=mid_test` did not return report 3882740 in the top 5.
- Rank 1 for this query is an RCE writeup (report 4077800,
  CWE-78), not a SQL injection writeup: keyword matching is
  literal, and "injection" in its title matches.

## Showcase 3

### Target

A new machine, nothing installed. The question is how fast it goes
from zero to a verified real result.

### Question

Can a fresh machine install the client and get a real writeup back
in under a minute?

### Steps

1. Fresh virtual environment, cold cache, install from a checkout:

   ```bash
   python3 -m venv /tmp/eunoia-showcase
   /tmp/eunoia-showcase/bin/pip install --no-cache-dir -q .
   ```

2. Check the hosted services:

   ```bash
   /tmp/eunoia-showcase/bin/eunoia doctor
   ```

3. Call the MCP server the same way an agent would
   (`search_writeups`, query `CSRF`, limit 3):

   ```bash
   curl -s -X POST http://129.150.57.82:10005/mcp \
     -H 'Content-Type: application/json' \
     -H 'Accept: application/json, text/event-stream' \
     -H 'Mcp-Name: search_writeups' \
     -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_writeups","arguments":{"query":"CSRF","limit":3}}}'
   ```

### Evidence

Measured 19 Nov 2026, on this machine:

- Fresh venv + `pip install .`: 7.1 s wall clock; `pip install`
  alone 3.3 s; venv 16 MB (base CLI only, no server dependencies).
- `eunoia doctor`: 1.9 s, exit 0:

  ```text
  API http://129.150.57.82:10004: OK (507 writeups active)
  MCP http://129.150.57.82:10005/mcp: OK (6 tools)
  search_writeups: OK
  OK
  ```

- MCP `search_writeups` for `CSRF` returns the same top result as
  the REST search in Showcase 1:
  [hackerone.com/reports/3882740](https://hackerone.com/reports/3882740),
  score 0.6745.

### Numbers

- About 9 seconds from a fresh virtual environment to a verified
  live result (7.1 s install + 1.9 s doctor).
- 507 writeups active, 6 MCP tools.

### Limitations

- Install needs a checkout: the `eunoia-agents` package is not on
  PyPI yet.
- `eunoia doctor` checks the hosted API and MCP server only. It
  does not test a real agent session; no logged-in agent session
  was used in this showcase.
- The times were measured on this machine; another machine will
  differ, mostly in download speed.
