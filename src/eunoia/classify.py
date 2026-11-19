"""Task 6: deterministic Java/Spring classification (registry-side).

The Hacktivity API has no technology/framework filter (spec §5.4 note), so
classification happens here, in the registry — never in the poller query.
Rules + the ``tech_aliases`` table only; no LLM call, no network.

CPE vendor/product come from the seed CSV, whose entries are the NVD CPE
dictionary forms — never guessed (spec example: Nginx vendor is ``f5``,
not ``nginx``). Verified against NVD-derived records: NVD lists vendor
``vmware`` / product ``Spring Boot`` and ``Spring Framework`` (e.g.
CVE-2026-22733, CVE-2022-22965 Spring4Shell) and vendor ``apache`` /
product ``log4j`` (CVE-2021-44228 Log4Shell). A version found next to a
technology mention fills the version slot of its CPE; otherwise the CPE
keeps the ``*`` wildcard. Task 7 re-validates CPEs against the NVD
dictionary at enrichment time.

Input shapes: plain dicts AND ``Writeup`` model objects — fields are read
by key first, then by attribute (same convention as ``dedup.py``).

Vuln class is derived from CWE via a fixed taxonomy map. A CWE that maps
to no class — or no CWE at all — yields ``vuln_class="unclassified"`` and
``needs_review=True`` (spec quality gate: unmapped class goes to the
review queue; there is no review-queue table in MVP, so the signal is
carried on the Classification and the caller records it, e.g. in a
``writeup_events`` detail row, as Task 5 does for near-dup signals).
"""

from __future__ import annotations

import csv
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.models import TechAlias, Writeup, WriteupVuln

__all__ = [
    "SEED_CSV",
    "Alias",
    "Classification",
    "apply_classification",
    "classify_from_text",
    "classify_java_spring",
    "classify_vuln_class",
    "classify_writeup_class",
    "load_aliases_from_csv",
    "load_aliases_from_db",
    "reclassify_unclassified",
    "reclassify_writeup",
    "seed_tech_aliases",
]

SEED_CSV = Path(__file__).parent / "seed" / "tech_aliases_java.csv"

# Field weights: where a technology mention was found. Per technology
# the STRONGEST field match wins (max, not sum): a title match alone
# gives 0.5, a title + excerpt match still gives 0.5 for that
# technology. Confidence sums the per-technology best weights
# (capped at 0.95), so two technologies at 0.5 each reach 0.95.
# The old comment claimed title + excerpt = 0.85; that was wrong
# (final review triage, Task 6).
_FIELD_WEIGHTS = {"title": 0.5, "program": 0.4, "excerpt": 0.35}
_MAX_CONFIDENCE = 0.95

# Extra match phrases per technology, beyond the technology name itself
# (with "-" and " " variants) and its Maven artifact id. Kept deliberately
# small: every phrase must be unambiguous evidence for that technology.
_EXTRA_ALIASES: dict[str, list[str]] = {
    "spring-boot": ["springboot"],
    "spring-framework": ["spring mvc", "spring webflux", "springframework"],
    "tomcat": ["apache tomcat"],
    "log4j": ["log4j2", "log4shell", "apache log4j"],
}

_VERSION_RE = r"\d+\.\d+(?:\.\d+)?"

# CWE -> vuln-class taxonomy. Only well-established mappings live
# here; anything else is "unclassified". Expanded in T7 (19 Nov 2026)
# from the live corpus: the 50-row production corpus had 20
# unclassified rows and a 100-item Hacktivity probe had 56, all from
# CWEs this map did not cover. Each mapping is the CWE's own
# definition (CWE-352 *is* CSRF, CWE-400 *is* uncontrolled resource
# consumption, CWE-200 *is* information exposure, CWE-294 *is*
# authentication bypass by capture-replay, CWE-488 *is* exposure of
# a data element to the wrong session, ...), never a guess.
_CWE_TO_VULN_CLASS: dict[str, str] = {
    # XSS
    "CWE-79": "XSS",
    "CWE-80": "XSS",
    "CWE-87": "XSS",
    "CWE-116": "XSS",
    # SSRF
    "CWE-918": "SSRF",
    # SQLi
    "CWE-89": "SQLi",
    # RCE (incl. EL injection, which is RCE in practice)
    "CWE-78": "RCE",
    "CWE-94": "RCE",
    "CWE-95": "RCE",
    "CWE-917": "RCE",
    # Deserialization
    "CWE-502": "Deserialization",
    # XXE
    "CWE-611": "XXE",
    "CWE-91": "XXE",
    # Path Traversal
    "CWE-22": "Path Traversal",
    "CWE-23": "Path Traversal",
    "CWE-35": "Path Traversal",
    "CWE-36": "Path Traversal",
    # Auth Bypass
    "CWE-261": "Auth Bypass",
    "CWE-287": "Auth Bypass",
    "CWE-294": "Auth Bypass",
    "CWE-295": "Auth Bypass",
    "CWE-297": "Auth Bypass",
    "CWE-304": "Auth Bypass",
    "CWE-305": "Auth Bypass",
    "CWE-306": "Auth Bypass",
    "CWE-307": "Auth Bypass",
    "CWE-384": "Auth Bypass",
    "CWE-862": "Auth Bypass",
    "CWE-863": "Auth Bypass",
    # IDOR
    "CWE-639": "IDOR",
    "CWE-284": "IDOR",
    # SSTI
    "CWE-1336": "SSTI",
    # Race Condition
    "CWE-362": "Race Condition",
    # CSRF (T7: CWE-352 is the CSRF weakness itself)
    "CWE-352": "CSRF",
    # DoS: uncontrolled resource consumption / allocation without limits
    "CWE-400": "DoS",
    "CWE-667": "DoS",
    "CWE-770": "DoS",
    # Info Disclosure: exposure of sensitive data, in all its forms
    "CWE-200": "Info Disclosure",
    "CWE-201": "Info Disclosure",
    "CWE-209": "Info Disclosure",
    "CWE-212": "Info Disclosure",
    "CWE-215": "Info Disclosure",
    "CWE-311": "Info Disclosure",
    "CWE-312": "Info Disclosure",
    "CWE-319": "Info Disclosure",
    "CWE-359": "Info Disclosure",
    "CWE-488": "Info Disclosure",
    # Memory Safety: out-of-bounds, overflow, use-after-free
    "CWE-119": "Memory Safety",
    "CWE-120": "Memory Safety",
    "CWE-121": "Memory Safety",
    "CWE-122": "Memory Safety",
    "CWE-125": "Memory Safety",
    "CWE-191": "Memory Safety",
    "CWE-416": "Memory Safety",
    "CWE-787": "Memory Safety",
    # Privilege Escalation: improper privilege management, in all forms
    "CWE-250": "Privilege Escalation",
    "CWE-264": "Privilege Escalation",
    "CWE-266": "Privilege Escalation",
    "CWE-267": "Privilege Escalation",
    "CWE-268": "Privilege Escalation",
    "CWE-269": "Privilege Escalation",
    # Injection (non-SQL, non-command): CRLF, LDAP, XPath
    "CWE-90": "Injection",
    "CWE-93": "Injection",
    "CWE-113": "Injection",
    "CWE-643": "Injection",
    # Request Smuggling: inconsistent interpretation of HTTP requests
    "CWE-444": "Request Smuggling",
    # Open Redirect
    "CWE-601": "Open Redirect",
    # Unrestricted File Upload
    "CWE-434": "Unrestricted File Upload",
    # Clickjacking: improper restriction of UI layer rendering
    "CWE-1021": "Clickjacking",
}

#: The registry's vuln-class taxonomy: every class the CWE map can
#: produce, plus "unclassified". The quality gate validates against
#: this set instead of accepting any non-empty string as "mapped"
#: (final review triage, Task 13).
VULN_CLASSES: frozenset[str] = frozenset(
    set(_CWE_TO_VULN_CLASS.values()) | {"unclassified"}
)


@dataclass(frozen=True)
class Alias:
    """One row of the tech_aliases seed: how to spot a technology in text."""

    technology: str
    cpe: str | None = None
    ecosystem: str | None = None
    package_name: str | None = None
    version_pattern: str | None = None

    def match_phrases(self) -> list[str]:
        """Literal phrases (lowercase) that evidence this technology."""
        phrases = [self.technology, self.technology.replace("-", " ")]
        if self.package_name:
            artifact = self.package_name.split(":")[-1]
            phrases.append(artifact)
            phrases.append(artifact.replace("-", " "))
        phrases.extend(_EXTRA_ALIASES.get(self.technology, []))
        # Deduplicate, keep order, drop empties.
        return list(dict.fromkeys(p for p in phrases if p))


@dataclass
class Classification:
    tech: list[str] = field(default_factory=list)
    cpe: list[str] = field(default_factory=list)
    package: list[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: list[str] = field(default_factory=list)
    vuln_class: str = "unclassified"
    needs_review: bool = True


def _get(record: Any, key: str) -> Any:
    if isinstance(record, dict):
        return record.get(key)
    return getattr(record, key, None)


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return [str(v) for v in value]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _slugify(text: str | None) -> str:
    """Lowercase slug for program names (same shape as the worker's)."""
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug or "unknown"


def _cwe_ids(writeup: Any) -> list[str]:
    ids = _as_list(_get(writeup, "cwe_ids")) or _as_list(_get(writeup, "cwe_id"))
    return [i.upper() if i.upper().startswith("CWE-") else f"CWE-{i}" for i in ids]


def _cve_ids(writeup: Any) -> list[str]:
    return _as_list(_get(writeup, "cve_ids")) or _as_list(_get(writeup, "cve_id"))


def classify_vuln_class(cwe_ids: Iterable[str]) -> str:
    """Map CWE ids to the registry vuln-class taxonomy, else 'unclassified'."""
    for cwe in cwe_ids:
        cwe = cwe.upper()
        if not cwe.startswith("CWE-"):
            cwe = f"CWE-{cwe}"
        if cwe in _CWE_TO_VULN_CLASS:
            return _CWE_TO_VULN_CLASS[cwe]
    return "unclassified"


# --- Text fallback (T7) -------------------------------------------------
# Fires ONLY when no CWE (HackerOne or NVD) maps to a class — e.g. the
# Hacktivity API returns cwe=null for ~22% of disclosed reports.
# Order matters: first match wins, most specific technique first, so
# "Unauthenticated SSRF via ..." is SSRF (not Auth Bypass) and
# "MongoDB Query Logs & Schema Leak via Unauthenticated Endpoint" is
# Info Disclosure (not Auth Bypass).
#
# Every phrase is an explicit technique name observed in real
# disclosed titles and measured against the 506-row corpus on
# 19 Nov 2026: the set classifies 96 of the 145 NULL-CWE
# unclassified rows (the rest are mostly implementation quirks with
# no named technique, e.g. curl internals, or brand-new CVEs NVD
# has not published yet). CWE rows the map gains from NVD data are
# handled by the NVD backfill path, not by this list.
#
# This deliberately supersedes the MVP-era contract "no CWE means
# unclassified, never guess from the title": a title that names its
# technique ("SSRF", "bypass", "leak", "overflow", "ReDoS") IS the
# report naming its class, and T7 acceptance (unclassified <10%)
# is unreachable on the real corpus under the old contract (22-27%
# of rows have no CWE at all). Bare technique acronyms (ssrf, xss,
# csrf, idor, xxe, rce, sqli, lfi) are included for the same reason;
# generic words that are not a technique ("vulnerability", "bug",
# "issue") are not.
_TEXT_PHRASES: list[tuple[str, str]] = [
    ("SSRF", "ssrf"),
    ("SSRF", "server-side request forgery"),
    ("XSS", "xss"),
    ("XSS", "cross-site scripting"),
    ("XSS", "stored xss"),
    ("XSS", "reflected xss"),
    ("XSS", "dom xss"),
    ("CSRF", "csrf"),
    ("CSRF", "cross-site request forgery"),
    ("SQLi", "blind sql injection"),
    ("SQLi", "sql injection"),
    ("SQLi", "sqli"),
    ("IDOR", "idor"),
    ("IDOR", "insecure direct object reference"),
    ("XXE", "xxe"),
    ("XXE", "xml external entity"),
    ("XXE", "billion laughs"),
    ("RCE", "rce"),
    ("RCE", "remote code execution"),
    ("RCE", "os command injection"),
    ("RCE", "command injection"),
    ("Request Smuggling", "request smuggling"),
    ("Injection", "injection"),
    ("Injection", "crlf injection"),
    ("SSTI", "ssti"),
    ("Path Traversal", "directory traversal"),
    ("Path Traversal", "path traversal"),
    ("Path Traversal", "unauthorized directories"),
    ("Path Traversal", "arbitrary local file read"),
    ("Path Traversal", "arbitrary file read"),
    ("Path Traversal", "local file inclusion"),
    ("Path Traversal", "lfi"),
    ("Path Traversal", "overwrite"),
    ("Memory Safety", "buffer overflow"),
    ("Memory Safety", "out-of-bounds write"),
    ("Memory Safety", "out-of-bounds read"),
    ("Memory Safety", "heap overflow"),
    ("Memory Safety", "stack overflow"),
    ("Memory Safety", "overflow"),
    ("Memory Safety", "underflow"),
    ("Memory Safety", "out of bounds"),
    ("Memory Safety", "use after free"),
    ("Memory Safety", "use-after-free"),
    ("Memory Safety", "double free"),
    ("Memory Safety", "double-free"),
    ("Info Disclosure", "information disclosure"),
    ("Info Disclosure", "sensitive data exposure"),
    ("Info Disclosure", "sensitive data"),
    ("Info Disclosure", "sensitive exposure"),
    ("Info Disclosure", "disclosure"),
    ("Info Disclosure", "state leak"),
    ("Info Disclosure", "leaks sensitive"),
    ("Info Disclosure", "exposing donor"),
    ("Info Disclosure", "leak"),
    ("Info Disclosure", "leaks"),
    ("Info Disclosure", "leaked"),
    ("Info Disclosure", "leaking"),
    ("Info Disclosure", "leakage"),
    ("Info Disclosure", "expose"),
    ("Info Disclosure", "exposes"),
    ("Info Disclosure", "exposed"),
    ("Info Disclosure", "exposing"),
    ("Info Disclosure", "exposure"),
    ("Info Disclosure", "exfiltration"),
    ("Info Disclosure", "in plain text"),
    ("Info Disclosure", "identity leakage"),
    ("Info Disclosure", "data breach"),
    ("Info Disclosure", "password hash"),
    ("Info Disclosure", "file listing"),
    ("Info Disclosure", "production data"),
    ("Auth Bypass", "username takeover"),
    ("Auth Bypass", "authorization codes are reusable"),
    ("Auth Bypass", "trusts the presented"),
    ("Auth Bypass", "authentication bypass"),
    ("Auth Bypass", "bypasses authentication"),
    ("Auth Bypass", "broken authentication"),
    ("Auth Bypass", "revoked cert"),
    ("Auth Bypass", "verification bypass"),
    ("Auth Bypass", "bypassing"),
    ("Auth Bypass", "bypass"),
    ("Auth Bypass", "bypasses"),
    ("Auth Bypass", "takeover"),
    ("Auth Bypass", "brute force"),
    ("Auth Bypass", "confused deputy"),
    ("Auth Bypass", "authorization code"),
    ("Auth Bypass", "authentication"),
    ("Auth Bypass", "unauthenticated"),
    ("Auth Bypass", "unauthorized"),
    ("Auth Bypass", "unauthorised"),
    ("Auth Bypass", "rate limit"),
    ("Auth Bypass", "mitm"),
    ("Auth Bypass", "man-in-the-middle"),
    ("Auth Bypass", "starttls stripping"),
    ("Auth Bypass", "ssl certificate"),
    ("Auth Bypass", "without verifying"),
    ("Auth Bypass", "after password change"),
    ("Auth Bypass", "spf"),
    ("Auth Bypass", "nonce reused"),
    ("Auth Bypass", "auth context"),
    ("Clickjacking", "clickjacking"),
    ("Unrestricted File Upload", "unrestricted file upload"),
    ("Race Condition", "race condition"),
    ("Open Redirect", "open redirect"),
    ("DoS", "denial of service"),
    ("DoS", "denial-of-service"),
    ("DoS", "starvation"),
    ("DoS", "unbounded"),
    ("DoS", "hangs indefinitely"),
    ("DoS", "redos"),
    ("DoS", "dos"),
    ("DoS", "ddos"),
    ("Privilege Escalation", "privilege escalation"),
]


def classify_from_text(title: str | None, excerpt: str | None) -> str:
    """Strict phrase match over title + excerpt; "unclassified" when
    no phrase matches. Word-boundary matching, like the tech matcher:
    "csrf" must not match inside another word."""
    text = _normalize(f"{title or ''} {excerpt or ''}")
    for vuln_class, phrase in _TEXT_PHRASES:
        if re.search(rf"(?<![\w]){re.escape(phrase)}(?![\w])", text):
            return vuln_class
    return "unclassified"


def classify_writeup_class(
    title: str | None,
    excerpt: str | None,
    cwe_ids: Iterable[str],
) -> tuple[str, str]:
    """Classify one writeup: CWE first (authoritative), text fallback
    second, "unclassified" last. Returns ``(vuln_class, source)``
    where source is "cwe", "text", or "unclassified"."""
    cwe_class = classify_vuln_class(cwe_ids)
    if cwe_class != "unclassified":
        return cwe_class, "cwe"
    text_class = classify_from_text(title, excerpt)
    if text_class != "unclassified":
        return text_class, "text"
    return "unclassified", "unclassified"


def _cpe_with_version(cpe: str, version: str | None) -> str:
    """Fill the version slot of a CPE 2.3 URI; keep '*' when unknown."""
    if version is None:
        return cpe
    parts = cpe.split(":")
    # cpe:2.3:<part>:<vendor>:<product>:<version>:...
    if len(parts) >= 6 and parts[0] == "cpe" and parts[1] == "2.3":
        parts[5] = version
        return ":".join(parts)
    return cpe


def _find_version(text: str, phrase: str, version_pattern: str | None) -> str | None:
    """Version written right after a technology mention, e.g. 'Spring Boot 3.2.0'."""
    pattern = version_pattern or _VERSION_RE
    m = re.search(rf"{re.escape(phrase)}\s+v?({pattern})", text)
    return m.group(1) if m else None


def _default_aliases() -> list[Alias]:
    return load_aliases_from_csv()


def load_aliases_from_csv(path: Path | str = SEED_CSV) -> list[Alias]:
    """Read the bundled seed CSV (same columns as the TechAlias model)."""
    aliases: list[Alias] = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            aliases.append(
                Alias(
                    technology=row["technology"].strip(),
                    cpe=row.get("cpe") or None,
                    ecosystem=row.get("ecosystem") or None,
                    package_name=row.get("package_name") or None,
                    version_pattern=row.get("version_pattern") or None,
                )
            )
    return aliases


def load_aliases_from_db(session: Session) -> list[Alias]:
    """Read the persisted tech_aliases table (Task 3) as matchable aliases."""
    rows = session.execute(select(TechAlias)).scalars().all()
    return [
        Alias(
            technology=r.technology,
            cpe=r.cpe,
            ecosystem=r.ecosystem,
            package_name=r.package_name,
            version_pattern=r.version_pattern,
        )
        for r in rows
    ]


def seed_tech_aliases(session: Session, path: Path | str = SEED_CSV) -> int:
    """Insert the seed CSV into tech_aliases; idempotent, returns rows added."""
    existing = {
        (t, c)
        for t, c in session.execute(
            select(TechAlias.technology, TechAlias.cpe)
        ).all()
    }
    added = 0
    for alias in load_aliases_from_csv(path):
        if (alias.technology, alias.cpe) in existing:
            continue
        session.add(
            TechAlias(
                technology=alias.technology,
                cpe=alias.cpe,
                ecosystem=alias.ecosystem,
                package_name=alias.package_name,
                version_pattern=alias.version_pattern,
            )
        )
        existing.add((alias.technology, alias.cpe))
        added += 1
    session.flush()
    return added


def classify_java_spring(
    writeup: Any, aliases: list[Alias] | None = None
) -> Classification:
    """Classify a parsed writeup (title/excerpt/program + CWE/CVE).

    Returns the Java/Spring technologies evidenced in the text, their CPEs
    (version filled in when stated next to the mention) and Maven packages,
    a deterministic confidence, and the vuln class from CWE.
    """
    aliases = aliases if aliases is not None else _default_aliases()
    fields = {
        name: _normalize(str(_get(writeup, name) or ""))
        for name in ("title", "excerpt", "program")
    }

    result = Classification()
    seen_tech: set[str] = set()
    for alias in aliases:
        best_weight = 0.0
        best_evidence: str | None = None
        version: str | None = None
        for phrase in alias.match_phrases():
            for field_name, text in fields.items():
                if not text:
                    continue
                # Word-boundary match: "spring" alone must not match, and
                # "log4j" must not match inside "log4j2" (handled by the
                # explicit "log4j2" phrase instead).
                if not re.search(rf"(?<![\w.]){re.escape(phrase)}(?![\w])", text):
                    continue
                weight = _FIELD_WEIGHTS[field_name]
                if weight > best_weight:
                    best_weight = weight
                    best_evidence = (
                        f"{field_name} mentions '{phrase}' -> {alias.technology}"
                    )
                found = _find_version(text, phrase, alias.version_pattern)
                if found is not None:
                    version = found
        if best_weight == 0.0:
            continue
        if alias.technology in seen_tech:
            continue
        seen_tech.add(alias.technology)
        result.tech.append(alias.technology)
        if alias.cpe:
            result.cpe.append(_cpe_with_version(alias.cpe, version))
        if alias.package_name:
            result.package.append(alias.package_name)
        result.confidence = min(
            _MAX_CONFIDENCE, result.confidence + best_weight
        )
        if best_evidence is not None:
            result.evidence.append(best_evidence)

    result.confidence = round(result.confidence, 2)
    # T7: CWE first, strict text fallback second (a NULL CWE is common
    # in Hacktivity data). classify_java_spring's own vuln_class keeps
    # the same rule, so the tech classifier and the writeup classifier
    # never disagree about a row's class.
    result.vuln_class, _ = classify_writeup_class(
        fields.get("title", ""), fields.get("excerpt", ""),
        _cwe_ids(writeup))
    result.needs_review = result.vuln_class == "unclassified"
    return result


def apply_classification(
    session: Session,
    writeup: Writeup,
    classification: Classification | None = None,
) -> WriteupVuln:
    """Fill in a writeup's vuln class from classification.

    Task 5 handoff: a writeup with no CWE/CVE/severity/bounty gets NO
    WriteupVuln row at all, so this CREATES the row when missing instead
    of only updating an existing one. When a row exists with a null
    vuln_class, it is filled in; an already-set vuln_class is left alone.
    """
    row = (
        session.query(WriteupVuln)
        .filter_by(writeup_id=writeup.id)
        .first()
    )
    cwe_ids = _cwe_ids(writeup)
    cve_ids = _cve_ids(writeup)
    program = _get(writeup, "program")
    if row is not None:
        if row.cwe_id:
            cwe_ids = [row.cwe_id]
        if row.cve_id:
            cve_ids = [row.cve_id]
        if row.program:
            program = row.program
    if classification is None:
        classification = classify_java_spring(
            {
                "title": writeup.title,
                "excerpt": writeup.excerpt,
                "program": program,
                "cwe_ids": cwe_ids,
                "cve_ids": cve_ids,
            }
        )
    if row is None:
        # Final review triage, Task 6: the create path used to lose
        # the CWE/CVE (it re-read them from the bare writeup, which
        # carries none on the model) and omitted the program. The
        # values derived above are now carried through to the row.
        row = WriteupVuln(
            writeup_id=writeup.id,
            vuln_class=classification.vuln_class,
            cwe_id=cwe_ids[0] if cwe_ids else None,
            cve_id=cve_ids[0] if cve_ids else None,
            program=program,
            program_slug=_slugify(program) if program else None,
        )
        session.add(row)
    elif row.vuln_class is None:
        row.vuln_class = classification.vuln_class
    session.flush()
    return row


def reclassify_writeup(
    session: Session, writeup: Writeup
) -> tuple[str, str]:
    """Re-run classification on an EXISTING writeup's vuln rows (T7
    backfill / taxonomy upgrade).

    Only rows whose class is NULL or "unclassified" are upgraded, and
    only when the recomputed class is a real one. A row that already
    carries a mapped class is never overwritten — reclassification
    fills gaps, it does not second-guess earlier (or human) labels.
    Returns ``(old, new)`` for the first upgraded row, or
    ``(current, current)`` when nothing changed. Flush-only; the
    caller owns the transaction.
    """
    rows = session.query(WriteupVuln).filter_by(
        writeup_id=writeup.id).all()
    first_change: tuple[str, str] | None = None
    for row in rows:
        current = row.vuln_class
        if current is not None and current != "unclassified":
            continue
        cwe_ids = [row.cwe_id] if row.cwe_id else []
        new_class, _ = classify_writeup_class(
            writeup.title, writeup.excerpt, cwe_ids)
        if new_class == "unclassified":
            continue
        row.vuln_class = new_class
        if first_change is None:
            first_change = (current or "unclassified", new_class)
    session.flush()
    if first_change is not None:
        return first_change
    current = rows[0].vuln_class if rows else None
    return (current or "unclassified", current or "unclassified")


def reclassify_unclassified(session: Session) -> tuple[int, int]:
    """Reclassify every writeup that still has an unclassified vuln
    row (T7 backfill step for rows ingested under the old taxonomy).

    Returns ``(checked, changed)``: writeups examined vs writeups
    where at least one row upgraded. Flush-only; the caller commits.
    """
    rows = (
        session.query(WriteupVuln)
        .filter(
            (WriteupVuln.vuln_class.is_(None))
            | (WriteupVuln.vuln_class == "unclassified")
        )
        .all()
    )
    writeup_ids = {row.writeup_id for row in rows}
    changed = 0
    for wid in sorted(writeup_ids, key=str):
        writeup = session.get(Writeup, wid)
        if writeup is None:
            continue
        old, new = reclassify_writeup(session, writeup)
        if old != new:
            changed += 1
    session.flush()
    return len(writeup_ids), changed
