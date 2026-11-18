"""Quality gate before a record goes live (spec §6.5).

Checks: (a) canonical URL resolves (200); (b) title/author/date parse;
(c) vuln class mapped to the taxonomy, else ``unclassified`` + review
queue; (d) no live credential/token in the excerpt (secret scan);
(e) language detected.

``passed`` is False when a hard check fails (URL, fields, secrets) —
the record must not go live. An unmapped class or undetected language
does not block the record but flags it ``needs_review``: it may go live
labeled ``unclassified`` and waits for a human in the review queue.
The URL check needs an injected ``url_checker`` (a callable returning
True for HTTP 200); without one the check is recorded as "skipped" and
the gate cannot pass — an unverified URL is not a verified one.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable

from eunoia.safety.secrets_scan import scan_secrets

_ENGLISH_STOPWORDS = frozenset(
    "the a an and or of to in is are was were it this that with for on by "
    "from as at be has have had not but they he she we you his her their "
    "vulnerability via server client request response".split())


@dataclass(frozen=True)
class QualityGateResult:
    passed: bool
    needs_review: bool
    vuln_class: str | None
    checks: dict[str, str] = field(default_factory=dict)


def detect_language(title: str | None, excerpt: str | None) -> str | None:
    """Naive language detection: English stopwords present → "en".

    MVP heuristic only — a real detector belongs here if non-English
    writeups are ever ingested (spec §9 Q6).
    """
    words = set((f"{title or ''} {excerpt or ''}").lower().split())
    if len(words & _ENGLISH_STOPWORDS) >= 2:
        return "en"
    return None


def _parse_date(value) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def quality_gate(*, canonical_url: str, title: str | None,
                 author_name: str | None, published_at,
                 vuln_class: str | None, excerpt: str | None,
                 language: str | None = None,
                 url_checker: Callable[[str], bool] | None = None
                 ) -> QualityGateResult:
    checks: dict[str, str] = {}

    # (a) Canonical URL resolves (200).
    if url_checker is None:
        checks["canonical_url"] = "skipped"
        url_ok = False
    else:
        try:
            url_ok = bool(url_checker(canonical_url))
        except Exception:
            url_ok = False
        checks["canonical_url"] = "pass" if url_ok else "fail"

    # (b) Title / author / date parse.
    fields_ok = bool((title or "").strip()
                     and (author_name or "").strip()
                     and _parse_date(published_at) is not None)
    checks["fields"] = "pass" if fields_ok else "fail"

    # (c) Vuln class mapped, else unclassified + review queue.
    mapped_class = (vuln_class or "").strip() or None
    needs_review = False
    if mapped_class and mapped_class != "unclassified":
        checks["vuln_class"] = "pass"
    else:
        mapped_class = "unclassified"
        checks["vuln_class"] = "review"
        needs_review = True

    # (d) No live credential/token in the excerpt.
    secrets_ok = not scan_secrets(excerpt)
    checks["secrets"] = "pass" if secrets_ok else "fail"

    # (e) Language detected.
    detected = language or detect_language(title, excerpt)
    if detected:
        checks["language"] = "pass"
    else:
        checks["language"] = "review"
        needs_review = True

    passed = url_ok and fields_ok and secrets_ok
    return QualityGateResult(passed=passed, needs_review=needs_review,
                             vuln_class=mapped_class, checks=checks)
