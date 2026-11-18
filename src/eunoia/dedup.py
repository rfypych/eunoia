"""5-layer dedup (spec §5.6).

Layer order (strongest first):
1. Canonical URL (exact, after normalization) — ``url_hash`` is the primary
   dedup key and a unique constraint on ``writeups``.
2. Platform external id (e.g. ``hackerone:689314``).
3. Exact content hash (SHA-256 of normalized text).
4. Near-duplicate SimHash 64-bit (Hamming distance <= 3) — review queue only.
   A near-dup NEVER auto-merges unless the canonical URL or external id
   also matches (layers 1-2 already decided that).
5. Title + author + date — fuzzy signal for the review queue only, never an
   auto-merge key.

Cross-posting is not duplication: one logical writeup, many ``source_urls``.
Records here are dicts or ``Writeup``-like objects; fields are read by key
first, then by attribute, so callers can pass either shape.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

__all__ = [
    "NEAR_DUP_HAMMING_MAX",
    "content_hash",
    "dedup_decision",
    "hamming_distance",
    "normalize_text",
    "normalize_url",
    "simhash64",
    "url_hash",
]

DedupDecision = Literal[
    "exact",
    "external_id",
    "content",
    "near_dup_review",
    "title_candidate",
    "new",
]

NEAR_DUP_HAMMING_MAX = 3

_TRACKING_PARAMS = ("fbclid",)
_TOKEN_RE = re.compile(r"[a-z0-9]+")


def _get(record: Any, key: str) -> Any:
    """Read ``key`` from a dict or an object attribute; ``None`` when absent."""
    if record is None:
        return None
    if isinstance(record, dict):
        return record.get(key)
    return getattr(record, key, None)


def normalize_url(url: str) -> str:
    """Canonical form of a URL for dedup.

    Lowercase scheme/host, strip default ports (80 http / 443 https), strip
    the fragment, drop tracking params (``utm_*``, ``fbclid``), sort the
    remaining query params.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    if port is not None and not (scheme == "http" and port == 80) and not (scheme == "https" and port == 443):
        host = f"{host}:{port}"
    if parsed.username:
        auth = parsed.username
        if parsed.password:
            auth += f":{parsed.password}"
        host = f"{auth}@{host}"
    params = [
        (k, v)
        for k, v in parse_qsl(parsed.query, keep_blank_values=True)
        if not k.startswith("utm_") and k not in _TRACKING_PARAMS
    ]
    query = urlencode(sorted(params))
    return urlunparse((scheme, host, parsed.path, parsed.params, query, ""))


def url_hash(url: str) -> str:
    """SHA-256 of the normalized URL — the primary dedup key."""
    return hashlib.sha256(normalize_url(url).encode("utf-8")).hexdigest()


def normalize_text(text: str) -> str:
    """Normalize extracted text for hashing: lowercase, collapse whitespace.

    Callers must strip site boilerplate (nav/footer chrome) before hashing;
    this function normalizes the already-extracted text.
    """
    return re.sub(r"\s+", " ", text.lower()).strip()


def content_hash(text: str) -> str:
    """SHA-256 of the normalized text."""
    return hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def simhash64(text: str) -> int:
    """64-bit SimHash over lowercased word tokens (stdlib only, deterministic).

    Each token contributes +1/-1 per bit of its MD5 hash; the sign of the
    per-bit sum decides the output bit.
    """
    weights = [0] * 64
    for token in _TOKEN_RE.findall(text.lower()):
        digest = int.from_bytes(hashlib.md5(token.encode("utf-8")).digest()[:8], "big")
        for bit in range(64):
            weights[bit] += 1 if (digest >> bit) & 1 else -1
    result = 0
    for bit, weight in enumerate(weights):
        if weight > 0:
            result |= 1 << bit
    return result


def hamming_distance(a: int, b: int) -> int:
    """Number of differing bits between two 64-bit SimHashes."""
    return bin(a ^ b).count("1")


def _text_of(record: Any) -> str | None:
    for key in ("text", "content", "normalized_text"):
        value = _get(record, key)
        if value:
            return str(value)
    return None


def _same_title_author_date(existing: Any, candidate: Any) -> bool:
    title_a = _get(existing, "title")
    title_b = _get(candidate, "title")
    if not title_a or not title_b:
        return False
    if normalize_text(str(title_a)) != normalize_text(str(title_b)):
        return False
    author_a = _get(existing, "author") or _get(existing, "author_name")
    author_b = _get(candidate, "author") or _get(candidate, "author_name")
    if not author_a or not author_b:
        return False
    if normalize_text(str(author_a)) != normalize_text(str(author_b)):
        return False
    date_a = _get(existing, "published_at") or _get(existing, "disclosed_at")
    date_b = _get(candidate, "published_at") or _get(candidate, "disclosed_at")
    if date_a is None or date_b is None:
        return True  # title + author match; no date to contradict
    # Compare by calendar day so "2026-01-05" and "2026-01-05T10:00:00Z" match.
    return str(date_a)[:10] == str(date_b)[:10]


def dedup_decision(existing: Any, candidate: Any) -> DedupDecision:
    """Decide how ``candidate`` relates to ``existing`` (strongest layer wins).

    Returns ``"near_dup_review"`` / ``"title_candidate"`` for the two weakest
    layers: those are review-queue signals, never auto-merge decisions.
    """
    url_a = _get(existing, "canonical_url")
    url_b = _get(candidate, "canonical_url")
    if url_a and url_b and url_hash(str(url_a)) == url_hash(str(url_b)):
        return "exact"

    ext_a = _get(existing, "external_id")
    ext_b = _get(candidate, "external_id")
    if ext_a and ext_b and str(ext_a) == str(ext_b):
        return "external_id"

    text_a = _text_of(existing)
    text_b = _text_of(candidate)
    if text_a and text_b:
        if content_hash(text_a) == content_hash(text_b):
            return "content"
        if hamming_distance(simhash64(text_a), simhash64(text_b)) <= NEAR_DUP_HAMMING_MAX:
            return "near_dup_review"

    if _same_title_author_date(existing, candidate):
        return "title_candidate"

    return "new"
