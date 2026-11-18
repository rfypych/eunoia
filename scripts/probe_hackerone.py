#!/usr/bin/env python3
"""Task 1 probe: one unauthenticated GET to HackerOne Hacktivity (spec §9 Q1).

Answers: does GET /v1/hackers/hacktivity work without a customer token?
Writes docs/probes/hackerone-auth-2026-11-18.md with the observed outcome.
No retry, no token, no credential. Stdlib only.
"""

import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

URL = "https://api.hackerone.com/v1/hackers/hacktivity?page[size]=1"
DOC_PATH = Path(__file__).resolve().parent.parent / "docs" / "probes" / "hackerone-auth-2026-11-18.md"


def probe() -> tuple[int, str]:
    req = urllib.request.Request(URL, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, f"URLError: {e.reason}"


def classify(status: int, body: str) -> str:
    if status == 200:
        return "no_auth_ok"
    if status == 403:
        return "plan_gated_403"
    if status == 401:
        return "token_required"
    # 429 (throttled), 5xx (server error), 0 (network failure) and any
    # other unexpected status are NOT auth evidence: they must not be
    # mislabelled as token_required, or Task 5 would chase a token
    # instead of backing off / retrying later.
    return "probe_failed"


def main() -> None:
    status, body = probe()
    outcome = classify(status, body)
    excerpt = body[:500]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    observation = ""
    if status == 200:
        try:
            items = json.loads(body).get("data", [])
            disclosed = sum(1 for i in items if i.get("attributes", {}).get("disclosed"))
            observation = (
                f"\n## Observation\n\n"
                f"- Items returned: `{len(items)}`; disclosed: `{disclosed}`.\n"
                f"- The first item in the default sort is undisclosed "
                f"(`disclosed: false`, `title: null`). Task 5 must filter/sort "
                f"for disclosed reports (e.g. sort `-disclosed_at`) instead of "
                f"taking the default first page as-is.\n"
            )
        except (json.JSONDecodeError, AttributeError):
            observation = "\n## Observation\n\n- Body was not parseable as JSON; see excerpt.\n"

    fallback = ""
    if outcome == "plan_gated_403":
        fallback = """
## Fallback

Do not build the poller on an assumption. Options, in order:
1. Customer token (HackerOne API token with Hacktivity entitlement).
2. HackerOne account token (free hacker account) — verify it grants
   Hacktivity read access before building on it.
3. Request a feed / partnership from HackerOne.
"""
    elif outcome == "token_required":
        fallback = """
## Fallback

Do not build the poller on an assumption. A token is required; obtain one
(customer token or HackerOne account token) and re-probe authenticated
before building the poller.
"""
    elif outcome == "probe_failed":
        fallback = """
## No decision — probe failed

The probe did not reach a conclusive auth answer (rate-limited, server
error, or network failure). This is NOT evidence that a token is required.
Do not seek a token on the basis of this run. Back off and re-probe later;
Task 5 must not be built on this outcome.
"""

    doc = f"""# HackerOne Hacktivity auth probe — {now}

**Question (spec §9 Q1):** does the HackerOne Hacktivity REST API work
without a customer token?

## Probe

- Request: `GET /v1/hackers/hacktivity?page[size]=1`
- Full URL: `{URL}`
- Auth: none (unauthenticated)
- Retries: none

## Observed result

- HTTP status: `{status}`
- Outcome: `{outcome}`
- Body excerpt (first 500 chars):

```json
{excerpt}
```
{observation}
{fallback}
## Decision for Task 5 (poller)

Outcome `{outcome}` is the input to Task 5. The poller must be built on
the auth mode recorded here, not on an assumption.
"""
    DOC_PATH.parent.mkdir(parents=True, exist_ok=True)
    DOC_PATH.write_text(doc, encoding="utf-8")
    print(f"HTTP {status}")
    print(f"outcome: {outcome}")
    print(excerpt)
    print(f"wrote {DOC_PATH}")


if __name__ == "__main__":
    main()
