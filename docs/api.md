# API

The hosted API is live at `http://129.150.57.82:10004`. No key is
needed for keyword search. The full schema is at
[OpenAPI](http://129.150.57.82:10004/api/v1/openapi.json), and the
machine-readable index is at
[llms.txt](http://129.150.57.82:10004/llms.txt). The website/demo
at the API root (`/`) has a search box that calls the same
endpoints.

## Endpoints

| Endpoint | What it returns |
| --- | --- |
| `GET /v1/status` | Source health: last poll, lag, failures, corpus size |
| `GET /v1/search?q=...` | Ranked writeups for a query |
| `GET /v1/writeups` | List of writeups (newest first) |
| `GET /v1/writeups/{id}` | One writeup: full metadata + canonical link |
| `GET /v1/writeups/{id}.md` | One writeup as Markdown |
| `GET /v1/writeups/{id}/skill.md` | A `SKILL.md` generated from that writeup |
| `GET /v1/vuln-classes` | Vulnerability classes with writeup counts |
| `GET /v1/vuln-classes/{class}/skill.md` | Aggregate skill for one class |
| `GET /v1/programs` | Bounty programs in the corpus |
| `GET /v1/authors` | Writeup authors in the corpus |
| `GET /llms.txt` | Machine-readable index (top writeups, policies) |
| `GET /api/v1/openapi.json` | OpenAPI schema |
| `GET /` | Website/demo page (HTML) |

## Search

```bash
# Pre-test: plan from recon (default ranking)
curl "http://129.150.57.82:10004/v1/search?q=SQL+injection&limit=5"

# Mid-test: stuck, or a suspicious candidate (mid-test ranking)
curl "http://129.150.57.82:10004/v1/search?q=IDOR&lookup=mid_test&limit=3"
```

Parameters:

- `q` — the query (technique, keyword, or stack).
- `lookup` — `pre_test` (default) or `mid_test`. Mid-test
  ranking weighs technique similarity more and recency less.
- `limit` — 1 to 10, default 5. A larger value is clamped to 10;
  the response reports the effective limit.
- `mode` — `keyword` (default for anonymous callers), `semantic`,
  or `hybrid`. Semantic and hybrid need an API key (see below).
- `vuln_class`, `cwe`, `tech` — filters; see the OpenAPI schema.

Each result carries the writeup id, title, excerpt, canonical
source link, severity, CWE/CVE ids, tech tags, and a score with
its breakdown. Scores move as the corpus grows; a result is a
past writeup with evidence, not a generated finding.

## Auth tiers and rate limits

| Tier | Search modes | Rate limit |
| --- | --- | --- |
| Anonymous (no key) | keyword only | 60 requests per minute |
| API key | keyword, semantic, hybrid | 600 requests per minute |

API keys are provisioned by the operator (there is no HTTP admin
route for provisioning); see [Runbook](runbook.md). Asking for
`semantic` or `hybrid` without a key returns 403
`MODE_REQUIRES_KEY`.

## Errors

| Status | Meaning |
| --- | --- |
| `400` | Bad request (bad parameter value). |
| `403` | `MODE_REQUIRES_KEY`: semantic/hybrid search needs an API key. |
| `404` | Unknown writeup id or unknown route. |
| `410` | `GONE`: the writeup was retracted or taken down and is no longer served. |
| `429` | Rate limit exceeded. |
| `501` | Reranking is not implemented (`rerank=true`). |
| `503` | `SECRET_FOUND`: a skill is blocked by the secret scan. |

## What the API does not do

- It never probes, scans, or attacks a target.
- It contains no payload library and executes no exploits.
- It is not a full-text mirror: it stores metadata and links to
  the canonical public disclosure; read the writeup at its source.
- It does not authorise testing. Every hypothesis it returns
  still needs explicit in-scope permission before any testing.
