"""Tests for the 5-layer dedup (spec §5.6).

Layer order (strongest first):
1. exact canonical URL (normalized)
2. platform external id
3. exact content hash
4. near-duplicate SimHash (Hamming <= 3) -> review queue, never auto-merge
5. title + author + date (fuzzy signal only, never an auto-merge key)
"""

from eunoia.dedup import (
    NEAR_DUP_HAMMING_MAX,
    content_hash,
    dedup_decision,
    hamming_distance,
    normalize_url,
    simhash64,
    url_hash,
)
from eunoia.models import Writeup


def _writeup(url: str, **kwargs) -> Writeup:
    """Real Task 3 Writeup object (in-memory, never persisted)."""
    return Writeup(canonical_url=url, url_hash=url_hash(url), title="SSRF on Example", **kwargs)


def test_writeup_objects_merge_by_external_id():
    a = _writeup("https://hackerone.com/reports/689314", external_id="hackerone:689314")
    b = _writeup("https://medium.com/@x/ssrf-abc", external_id="hackerone:689314")
    assert dedup_decision(a, b) == "external_id"


def test_writeup_objects_merge_by_stored_content_hash():
    digest = content_hash("ssrf via pdf parser in a spring boot application")
    a = _writeup("https://example.com/a", content_hash=digest)
    b = _writeup("https://example.com/b", content_hash=digest)
    assert dedup_decision(a, b) == "content"


def test_writeup_objects_near_dup_by_stored_simhash():
    base = (
        "ssrf via pdf parser in a spring boot application running on tomcat "
        "the parser fetched a remote url and returned internal metadata"
    )
    changed = base.replace("tomcat", "jetty")
    assert hamming_distance(simhash64(base), simhash64(changed)) <= NEAR_DUP_HAMMING_MAX
    a = _writeup("https://example.com/a", simhash=simhash64(base))
    b = _writeup("https://example.com/b", simhash=simhash64(changed))
    assert dedup_decision(a, b) == "near_dup_review"


def test_writeup_objects_exact_by_url():
    a = _writeup("https://hackerone.com/reports/1")
    b = _writeup("https://hackerone.com/reports/1?utm_campaign=y")
    assert dedup_decision(a, b) == "exact"


def test_same_report_different_urls_merges_by_external_id():
    a = {"canonical_url": "https://hackerone.com/reports/689314", "external_id": "hackerone:689314"}
    b = {"canonical_url": "https://medium.com/@x/ssrf-abc", "external_id": "hackerone:689314"}
    assert dedup_decision(a, b) == "external_id"


def test_utm_params_do_not_create_new_url():
    assert normalize_url("https://hackerone.com/reports/1?utm_source=x") == "https://hackerone.com/reports/1"


def test_normalize_url_lowercases_scheme_and_host():
    assert normalize_url("HTTPS://HackerOne.COM/reports/1") == "https://hackerone.com/reports/1"


def test_normalize_url_strips_default_port_and_fragment():
    assert normalize_url("https://hackerone.com:443/reports/1#section") == "https://hackerone.com/reports/1"
    assert normalize_url("http://example.com:80/x") == "http://example.com/x"


def test_normalize_url_drops_tracking_params_and_sorts_rest():
    assert (
        normalize_url("https://example.com/x?b=2&utm_medium=email&a=1&fbclid=abc")
        == "https://example.com/x?a=1&b=2"
    )


def test_url_hash_is_sha256_of_normalized_url():
    import hashlib

    assert url_hash("HTTPS://HackerOne.COM/reports/1?utm_source=x") == hashlib.sha256(
        b"https://hackerone.com/reports/1"
    ).hexdigest()


def test_same_url_is_exact_even_with_tracking_params():
    a = {"canonical_url": "https://hackerone.com/reports/1"}
    b = {"canonical_url": "https://hackerone.com/reports/1?utm_campaign=y"}
    assert dedup_decision(a, b) == "exact"


def test_content_hash_ignores_case_and_whitespace():
    assert content_hash("  SSRF   via\nPDF Parser ") == content_hash("ssrf via pdf parser")


def test_content_hash_differs_for_different_text():
    assert content_hash("ssrf via pdf parser") != content_hash("stored xss in comment field")


def test_same_content_different_url_merges_by_content():
    text = "ssrf via pdf parser in a spring boot application"
    a = {"canonical_url": "https://example.com/a", "text": text}
    b = {"canonical_url": "https://example.com/b", "text": "  SSRF   via PDF parser in a spring boot application "}
    assert dedup_decision(a, b) == "content"


def test_simhash_is_deterministic_and_zero_distance_for_identical_text():
    text = "ssrf via pdf parser in a spring boot application with tomcat"
    assert simhash64(text) == simhash64(text)
    assert hamming_distance(simhash64(text), simhash64(text)) == 0


def test_simhash_near_duplicate_goes_to_review_not_auto_merge():
    base = (
        "ssrf via pdf parser in a spring boot application running on tomcat "
        "the parser fetched a remote url and returned internal metadata"
    )
    changed = base.replace("tomcat", "jetty")
    assert hamming_distance(simhash64(base), simhash64(changed)) <= NEAR_DUP_HAMMING_MAX
    a = {"canonical_url": "https://example.com/a", "text": base}
    b = {"canonical_url": "https://example.com/b", "text": changed}
    assert dedup_decision(a, b) == "near_dup_review"


def test_unrelated_text_is_new():
    a = {"canonical_url": "https://example.com/a", "text": "ssrf via pdf parser"}
    b = {"canonical_url": "https://example.com/b", "text": "stored xss in comment field on wordpress"}
    assert dedup_decision(a, b) == "new"


def test_title_author_date_is_only_a_review_signal():
    a = {
        "canonical_url": "https://example.com/a",
        "title": "SSRF on Example ($500)",
        "author": "alice",
        "published_at": "2026-01-05",
    }
    b = {
        "canonical_url": "https://example.com/b",
        "title": "SSRF on Example ($500)",
        "author": "alice",
        "published_at": "2026-01-05T10:00:00Z",
    }
    assert dedup_decision(a, b) == "title_candidate"


def test_same_title_different_author_is_new():
    a = {"canonical_url": "https://example.com/a", "title": "SSRF on Example", "author": "alice"}
    b = {"canonical_url": "https://example.com/b", "title": "SSRF on Example", "author": "bob"}
    assert dedup_decision(a, b) == "new"


def test_exact_url_beats_external_id():
    a = {"canonical_url": "https://hackerone.com/reports/1", "external_id": "hackerone:1"}
    b = {"canonical_url": "https://hackerone.com/reports/1", "external_id": "hackerone:999"}
    assert dedup_decision(a, b) == "exact"


def test_simhash_round_trips_through_signed_bigint():
    # ~half of all SimHashes exceed the signed bigint max; a stored value
    # must still compare equal to the text-derived one (Task 5 worker).
    from eunoia.dedup import simhash_to_db

    text = "IDOR on profile API IDOR on profile API"
    raw = simhash64(text)
    assert raw > (1 << 63) - 1  # this text is one of the overflowing cases
    stored = simhash_to_db(raw)
    assert -(1 << 63) <= stored < (1 << 63)
    assert hamming_distance(stored, raw) == 0
    assert hamming_distance(-1, 0) == 64
