# HackerOne Hacktivity auth probe — 2026-11-18 15:06 UTC

**Question:** does the HackerOne Hacktivity REST API work
without a customer token?

## Probe

- Request: `GET /v1/hackers/hacktivity?page[size]=1`
- Full URL: `https://api.hackerone.com/v1/hackers/hacktivity?page[size]=1`
- Auth: none (unauthenticated)
- Retries: none

## Observed result

- HTTP status: `200`
- Outcome: `no_auth_ok`
- Body excerpt (first 500 chars):

```json
{"data":[{"id":4143164,"type":"hacktivity_item","attributes":{"title":null,"substate":null,"url":null,"disclosed_at":null,"vulnerability_information":null,"cve_ids":null,"cwe":null,"severity_rating":null,"votes":0,"total_awarded_amount":null,"latest_disclosable_action":"Activities::BugResolved","latest_disclosable_activity_at":"2026-11-18T14:51:14.218Z","submitted_at":"2026-10-24T20:43:34.293Z","disclosed":false},"relationships":{"reporter":{"data":{"type":"user","attributes":{"name":"Oxylis","u
```


## Observation

- Items returned: `1`; disclosed: `0`.
- The first item in the default sort is undisclosed (`disclosed: false`,
  `title: null`). The poller must filter/sort for disclosed reports
  (e.g. sort `-disclosed_at`) instead of taking the default first page
  as-is.

## Decision for the poller

Outcome `no_auth_ok`: the poller is built on the auth mode recorded
here, not on an assumption.
