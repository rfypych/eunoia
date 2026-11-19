"""NVD API 2.0 client + FIRST EPSS client (spec §5.4.5, §5.9).

Rate limits (NVD API 2.0): 5 requests per 30 seconds without a key,
50 per 30 seconds with a free API key (header ``apiKey``). The client
enforces the limit with a token bucket *before* issuing a request and
surfaces HTTP 429 as ``NvdRateLimitedError`` so callers can degrade to
cache instead of blocking ingestion (Review Focus 2).

HTTP client construction avoids this VM's ``NO_PROXY`` crash: httpx
parses ``NO_PROXY`` into URL patterns at ``Client`` construction and
chokes on bracketed IPv6 entries (``[::1]`` → ``Invalid port: ':1]'``),
so the proxy URL is read from the environment and passed explicitly
with ``trust_env=False`` (same approach as the HackerOne poller).
"""

from __future__ import annotations

import os
import re
import ssl
import time
from dataclasses import dataclass, field

import httpx

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# (requests, window seconds) per NVD's published limits.
NVD_RATE_LIMIT_NO_KEY = (5, 30)
NVD_RATE_LIMIT_WITH_KEY = (50, 30)

_CWE_RE = re.compile(r"^CWE-\d+$")


class NvdError(Exception):
    """NVD request failed for a reason other than rate limiting."""


class NvdRateLimitedError(NvdError):
    """Local bucket empty, or NVD answered HTTP 429."""


def default_http_client() -> httpx.Client:
    """Build an HTTP client that never re-parses this VM's environment.

    See the module docstring: httpx's env-proxy parser crashes on the
    bracketed IPv6 entries in ``NO_PROXY`` here.

    T7: like the HackerOne client, pass ``SSL_CERT_FILE`` explicitly
    when set — ``trust_env=False`` makes httpx ignore it, and the
    egress proxy's MITM CA is not in certifi's bundle. A context
    built from the bundle (a plain path string is deprecated).
    """
    proxy = (
        os.environ.get("HTTPS_PROXY")
        or os.environ.get("https_proxy")
        or os.environ.get("HTTP_PROXY")
        or os.environ.get("http_proxy")
    )
    kwargs: dict[str, object] = {
        "timeout": 30.0, "proxy": proxy or None, "trust_env": False,
    }
    ca_bundle = os.environ.get("SSL_CERT_FILE")
    if ca_bundle:
        kwargs["verify"] = ssl.create_default_context(cafile=ca_bundle)
    return httpx.Client(**kwargs)  # type: ignore[arg-type]


@dataclass
class TokenBucket:
    """Token bucket: ``capacity`` tokens refill over ``per_seconds``.

    ``try_acquire`` never sleeps — a caller that cannot get a token must
    degrade (serve from cache) instead of blocking ingestion.
    """

    capacity: int
    per_seconds: float
    _tokens: float = field(init=False)
    _updated_at: float = field(init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.capacity)
        self._updated_at = time.monotonic()

    def try_acquire(self, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self._updated_at)
        self._tokens = min(
            float(self.capacity),
            self._tokens + elapsed * (self.capacity / self.per_seconds),
        )
        self._updated_at = now
        if self._tokens < 1.0:
            return False
        self._tokens -= 1.0
        return True

    def available(self, now: float | None = None) -> float:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self._updated_at)
        return min(
            float(self.capacity),
            self._tokens + elapsed * (self.capacity / self.per_seconds),
        )


# One bucket per auth mode; the bucket is keyed by whether a key is sent,
# because the limit differs (5/30s vs 50/30s).
_BUCKET_NO_KEY = TokenBucket(*NVD_RATE_LIMIT_NO_KEY)
_BUCKET_WITH_KEY = TokenBucket(*NVD_RATE_LIMIT_WITH_KEY)


def _bucket_for(api_key: str | None) -> TokenBucket:
    return _BUCKET_WITH_KEY if api_key else _BUCKET_NO_KEY


def parse_nvd_cve(payload: dict) -> dict | None:
    """Normalize one NVD API 2.0 CVE payload into flat fields.

    Returns ``None`` when the payload carries no vulnerability (e.g. a
    200 with ``totalResults == 0``). CVSS prefers the ``Primary``
    metric, else the first metric of the newest version present
    (3.1 → 3.0 → 2.0). CWE ids come from ``weaknesses`` descriptions,
    ignoring ``NVD-CWE-noinfo`` / ``NVD-CWE-Other`` placeholders.
    """
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return None
    cve = vulns[0].get("cve") or {}
    cvss_score: float | None = None
    cvss_vector: str | None = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = (cve.get("metrics") or {}).get(key) or []
        if not metrics:
            continue
        metric = next((m for m in metrics if m.get("type") == "Primary"), metrics[0])
        data = metric.get("cvssData") or {}
        if data.get("baseScore") is not None:
            cvss_score = float(data["baseScore"])
            cvss_vector = data.get("vectorString")
        break
    cwe_ids: list[str] = []
    for weakness in cve.get("weaknesses") or []:
        for desc in weakness.get("description") or []:
            value = desc.get("value") or ""
            if _CWE_RE.match(value) and value not in cwe_ids:
                cwe_ids.append(value)
    return {
        "cve_id": cve.get("id"),
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe_ids": cwe_ids,
    }


def fetch_cve(
    cve_id: str,
    client: httpx.Client | None = None,
    api_key: str | None = None,
    limiter: TokenBucket | None = None,
) -> dict | None:
    """Fetch one CVE from NVD API 2.0, normalized via :func:`parse_nvd_cve`.

    Returns ``None`` for HTTP 404 (unknown to NVD). Raises
    ``NvdRateLimitedError`` when the token bucket is empty or NVD
    answers 429, and ``NvdError`` for other HTTP failures.
    """
    bucket = limiter if limiter is not None else _bucket_for(api_key)
    if not bucket.try_acquire():
        raise NvdRateLimitedError(
            f"NVD rate limit bucket empty for {cve_id} "
            f"({bucket.capacity}/{bucket.per_seconds}s)"
        )
    own_client = client is None
    http = client or default_http_client()
    try:
        headers = {"apiKey": api_key} if api_key else {}
        response = http.get(
            NVD_API_URL,
            params={"cveId": cve_id, "resultsPerPage": 1},
            headers=headers,
        )
    finally:
        if own_client:
            http.close()
    if response.status_code == 404:
        return None
    if response.status_code == 429:
        raise NvdRateLimitedError(f"NVD answered 429 for {cve_id}")
    if response.status_code != 200:
        raise NvdError(f"NVD answered {response.status_code} for {cve_id}")
    try:
        # Task 7 triage item: a malformed 200 body used to raise a
        # bare ValueError from response.json()/parse_nvd_cve, which
        # enrich_cve did not catch — it is an NVD failure, so wrap it
        # as NvdError and let the caller degrade to cache.
        return parse_nvd_cve(response.json())
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise NvdError(f"NVD returned a malformed body for {cve_id}: {exc}")


def fetch_epss(
    cve_id: str, client: httpx.Client | None = None
) -> tuple[float | None, float | None]:
    """Fetch FIRST EPSS score + percentile for one CVE.

    Best effort by design (EPSS is optional in the plan): any failure —
    HTTP error, missing data, malformed payload — returns ``(None, None)``
    instead of raising, so enrichment never blocks on EPSS.
    """
    own_client = client is None
    http = client or default_http_client()
    try:
        response = http.get(EPSS_API_URL, params={"cve": cve_id})
        if response.status_code != 200:
            return None, None
        rows = (response.json() or {}).get("data") or []
        if not rows:
            return None, None
        row = rows[0]
        try:
            return float(row["epss"]), float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            return None, None
    except (httpx.HTTPError, ValueError):
        # HTTP failure or a malformed (non-JSON) payload: EPSS is best
        # effort, so any failure degrades to (None, None).
        return None, None
    finally:
        if own_client:
            http.close()
