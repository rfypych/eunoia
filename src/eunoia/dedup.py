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

Input shapes supported: plain dicts AND ``Writeup`` model objects — fields
are read by key first, then by attribute, so callers (e.g. the Task 5 worker
upsert, which compares a candidate against persisted DB rows) can pass
either shape.

Layers 3–4 work two ways. When both records carry text (``text`` /
``content`` / ``normalized_text``), the text is hashed / SimHashed on the
fly. When no text is present — the normal case for persisted ``Writeup``
rows, whose full text is never stored — the stored fields are compared
instead: equal ``content_hash`` → ``"content"``, and stored ``simhash``
values with Hamming distance <= 3 → ``"near_dup_review"``. Mixed shapes
(one side text, the other side stored hashes) are compared the same way.
``excerpt`` is deliberately NOT used as the text: it is a <=300-char
truncated field, not the normalized text the content hash is defined over.

Boilerplate stripping remains the parser's job: ``normalize_text`` only
lowercases and collapses whitespace; the caller must strip site boilerplate
(nav/footer chrome) before hashing.
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
    "simhash_to_db",
    "url_hash",
]

_MASK64 = (1 << 64) - 1
_INT64_MAX = (1 << 63) - 1

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
    """Number of differing bits between two 64-bit SimHashes.

    Both operands are masked to 64 bits first: a SimHash stored in a signed
    Postgres ``bigint`` comes back negative for values >= 2**63, and
    ``bin()`` of a negative int does not count two's-complement bits.
    """
    return bin((a & _MASK64) ^ (b & _MASK64)).count("1")


def simhash_to_db(value: int) -> int:
    """Map an unsigned 64-bit SimHash into the signed ``bigint`` range.

    Values >= 2**63 are stored as their two's-complement negative; they
    round-trip exactly through ``hamming_distance`` (which masks to 64
    bits), so stored-vs-text comparisons stay correct.
    """
    value &= _MASK64
    return value - (1 << 64) if value > _INT64_MAX else value


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

    # Stored-field fallback (layers 3-4 for persisted Writeup rows, which
    # carry no text): compare content_hash / simhash directly, or cross
    # one side's text against the other side's stored hash.
    hash_a = _get(existing, "content_hash")
    hash_b = _get(candidate, "content_hash")
    if hash_a and hash_b and str(hash_a) == str(hash_b):
        return "content"
    if text_a and hash_b and content_hash(text_a) == str(hash_b):
        return "content"
    if text_b and hash_a and content_hash(text_b) == str(hash_a):
        return "content"

    sim_a = _get(existing, "simhash")
    sim_b = _get(candidate, "simhash")
    if sim_a is not None and sim_b is not None:
        if hamming_distance(int(sim_a), int(sim_b)) <= NEAR_DUP_HAMMING_MAX:
            return "near_dup_review"
    if text_a and sim_b is not None:
        if hamming_distance(simhash64(text_a), int(sim_b)) <= NEAR_DUP_HAMMING_MAX:
            return "near_dup_review"
    if text_b and sim_a is not None:
        if hamming_distance(int(sim_a), simhash64(text_b)) <= NEAR_DUP_HAMMING_MAX:
            return "near_dup_review"

    if _same_title_author_date(existing, candidate):
        return "title_candidate"

    return "new"
