"""SKILL.md generator, three layers (spec §5.11).

Layers: (1) registry skill — how to call REST/MCP, Lookup #1 vs #2,
token limits; (2) per-vuln-class skill — aggregate of the best verified
writeups in that class; (3) per-writeup skill — technique summary for
one writeup.

Content rules (binding, Review Focus 5): technique pattern and
vulnerability class only. No copy-paste payload that works against a
live target, no target URL outside the References links, no credential,
no step-by-step execution against a named live system. The exact PoC
stays behind the canonical link. ``references`` hold links only.

Skills are generated on demand from the current writeup row, so a
``content_hash`` change is reflected on the next call — there is no
stored skill that can go stale.
"""

from __future__ import annotations

import re
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.models import Writeup, WriteupVuln
from eunoia.safety.secrets_scan import SecretFoundError, scan_secrets
from eunoia.safety.serving import ensure_servable

MAX_NAME_LEN = 64
MAX_BODY_LINES = 500
MAX_TOKENS = 5000

_LAB_LIST = (
    "PortSwigger Academy, DVWA, HackTheBox, TryHackMe, or an in-scope "
    "bug bounty program that explicitly allows the technique"
)

_PLATFORM_SHORT = {
    "hackerone": "h1",
    "bugcrowd": "bc",
    "intigriti": "ig",
}

# Generic technique patterns, one per known vuln class. These describe
# the class of flaw in general terms; they never name a live target.
_CLASS_PATTERNS = {
    "ssrf": (
        "Server-Side Request Forgery happens when a server fetches a URL "
        "supplied by the user without checking where it points. The "
        "pattern to study is how the URL is validated, which schemes and "
        "hosts are allowed, and whether internal addresses can be "
        "reached through the fetcher."
    ),
    "xss": (
        "Cross-Site Scripting happens when user-controlled input is "
        "reflected or stored and later rendered as code in a browser. "
        "The pattern to study is where input enters the page, how it is "
        "encoded, and which contexts allow script execution."
    ),
    "sqli": (
        "SQL Injection happens when user-controlled input is concatenated "
        "into a database query. The pattern to study is how input reaches "
        "the query, whether the query is parameterized, and which "
        "characters change the query structure."
    ),
    "rce": (
        "Remote Code Execution happens when attacker-controlled input "
        "reaches a code execution sink. The pattern to study is the data "
        "flow from input to sink and which validation or sandboxing sits "
        "in between."
    ),
    "idor": (
        "Insecure Direct Object Reference happens when an object "
        "identifier in a request is not checked against the caller's "
        "permissions. The pattern to study is which identifiers are "
        "user-controlled and where the ownership check is missing."
    ),
    "deserialization": (
        "Unsafe deserialization happens when untrusted bytes are turned "
        "back into objects. The pattern to study is which classes can be "
        "instantiated from the stream and what their side effects are."
    ),
    "xxe": (
        "XML External Entity injection happens when an XML parser "
        "resolves external entities. The pattern to study is the parser "
        "configuration and whether entity expansion is disabled."
    ),
    "ssti": (
        "Server-Side Template Injection happens when user input is "
        "embedded into a template. The pattern to study is which "
        "template constructs are reachable from input."
    ),
    "auth bypass": (
        "Authentication bypass happens when a check meant to prove "
        "identity can be skipped or confused. The pattern to study is the "
        "exact check, its order, and what happens on each failure path."
    ),
    "race condition": (
        "A race condition happens when two operations that must be "
        "ordered can interleave. The pattern to study is the window "
        "between check and use and whether the operation is atomic."
    ),
    "path traversal": (
        "Path traversal happens when user-controlled path segments escape "
        "the intended directory. The pattern to study is how the path is "
        "built, normalized, and checked."
    ),
    "api abuse": (
        "API abuse happens when an API endpoint trusts client-supplied "
        "data it should verify. The pattern to study is which fields are "
        "trusted and where server-side validation is missing."
    ),
    "prompt injection": (
        "Prompt injection happens when untrusted content in the data an "
        "agent reads is treated as an instruction. The pattern to study "
        "is the boundary between data and instruction in the agent loop."
    ),
}


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return slug or "unknown"


def _platform_suffix(writeup: Writeup) -> str:
    """Deterministic platform suffix from ``external_id``.

    ``hackerone:689314`` -> ``h1-689314``. Without an external id, fall
    back to the first 8 hex digits of the writeup UUID.
    """
    external_id = writeup.external_id or ""
    if ":" in external_id:
        platform, numeric = external_id.split(":", 1)
        short = _PLATFORM_SHORT.get(platform.lower(), _slugify(platform))
        return f"{short}-{_slugify(numeric)}"
    if external_id:
        return _slugify(external_id)
    return f"w-{writeup.id.hex[:8]}"


def skill_name(writeup: Writeup, vuln: WriteupVuln | None) -> str:
    """Deterministic skill name: vuln-class + slug + platform-id.

    The title slug drops a leading copy of the class slug, so the
    canonical example is ``ssrf-via-pdf-parser-h1-689314``, not
    ``ssrf-ssrf-via-pdf-parser-h1-689314``.
    """
    vuln_class = _slugify(vuln.vuln_class) if vuln and vuln.vuln_class \
        else "unclassified"
    title_slug = _slugify(writeup.title)
    if title_slug.startswith(vuln_class + "-"):
        title_slug = title_slug[len(vuln_class) + 1:]
    name = "-".join([
        vuln_class,
        title_slug,
        _platform_suffix(writeup),
    ])
    return name[:MAX_NAME_LEN].rstrip("-")


def _frontmatter(name: str, description: str) -> str:
    # Description is a plain YAML scalar: no colons, under 1024 chars.
    description = " ".join(description.split())
    if len(description) > 1024:
        description = description[:1021].rstrip() + "..."
    return f"---\nname: {name}\ndescription: {description}\n---"


def _safe_practice_section() -> str:
    # The section name is lowercase, exactly as the spec names it.
    return (
        "## berlatih dengan aman\n"
        "\n"
        "Practice this technique only in a lab (" + _LAB_LIST + "). "
        "Only test systems you have written authorization to test. "
        "Reading a writeup is not permission to test a target.\n"
    )


def _class_pattern(vuln_class: str | None) -> str:
    key = (vuln_class or "").lower()
    if key in _CLASS_PATTERNS:
        return _CLASS_PATTERNS[key]
    label = vuln_class or "unknown class"
    return (
        f"This writeup documents a {label} technique. Study the pattern "
        "in general terms, the class of flaw, and how the vulnerable "
        "flow is structured, without reproducing the exact exploit."
    )


def _resolve_writeup(writeup_id: str | uuid.UUID,
                     session: Session) -> Writeup:
    """Resolve an API id (``w_<hex>``), a raw hex id, or a UUID."""
    if isinstance(writeup_id, uuid.UUID):
        parsed = writeup_id
    else:
        raw = str(writeup_id).strip()
        if raw.startswith("w_"):
            raw = raw[2:]
        try:
            parsed = uuid.UUID(hex=raw)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"not a writeup id: {writeup_id!r}") from exc
    writeup = session.get(Writeup, parsed)
    if writeup is None:
        raise ValueError(f"no writeup with id: {writeup_id!r}")
    return writeup


def _first_vuln(session: Session, writeup_id: uuid.UUID) -> WriteupVuln | None:
    return session.execute(
        select(WriteupVuln)
        .where(WriteupVuln.writeup_id == writeup_id)
        .order_by(WriteupVuln.id)
        .limit(1)
    ).scalars().first()


def _own_session() -> Session:
    return Session(get_engine(get_settings()))


def get_skill_text(writeup_id: str | uuid.UUID,
                   session: Session | None = None) -> str:
    """Per-writeup SKILL.md text for one writeup id.

    Raises ``ValueError`` for an unknown id. Raises
    ``NotServableError`` (Task 16 shared serving gate, Ruling R10)
    for a writeup whose status is not ``active``/``updated`` or
    whose quality gate failed: a retracted or taken-down disclosure
    is removed from serving and kept only as a stub, so no skill is
    generated for it. Raises ``SecretFoundError`` (a distinct type,
    not ``ValueError``) when the rendered skill trips the secret
    scan, so serving layers do not misreport the safety refusal as
    410 Gone.
    """
    own_session = session is None
    if own_session:
        session = _own_session()
    assert session is not None
    try:
        writeup = _resolve_writeup(writeup_id, session)
        ensure_servable(writeup)
        vuln = _first_vuln(session, writeup.id)
        text = _render_writeup_skill(writeup, vuln)
        # Task 13 (spec §6.5 gate (d)): defense in depth — the renderer
        # is payload-free by construction, but a secret that slips into
        # a title or field must never be served as a skill.
        findings = scan_secrets(text)
        if findings:
            raise SecretFoundError(
                f"skill for writeup {writeup.api_id} contains a "
                f"possible secret ({findings[0].pattern}); refusing to serve"
            )
        return text
    finally:
        if own_session:
            session.close()


def _render_writeup_skill(writeup: Writeup,
                          vuln: WriteupVuln | None) -> str:
    name = skill_name(writeup, vuln)
    vuln_class = vuln.vuln_class if vuln and vuln.vuln_class else None
    cwe = vuln.cwe_id if vuln else None
    cve = vuln.cve_id if vuln else None
    program = vuln.program if vuln else None

    class_label = vuln_class or "unclassified"
    description = (
        f"{class_label} technique from an authorized public disclosure. "
        "Only test systems you have written authorization to test. "
        "Describes the vulnerability pattern only, never a live payload, "
        "exact exploit code, or a target URL."
    )

    summary = [f"This writeup documents {writeup.title}."]
    if cwe:
        summary.append(f"It is classified as {class_label} ({cwe}).")
    elif vuln_class:
        summary.append(f"It is classified as {class_label}.")
    if program:
        summary.append(f"The affected program is {program}.")
    if cve:
        summary.append(f"It is linked to {cve}.")

    lines = [
        _frontmatter(name, description),
        "",
        f"# {writeup.title}",
        "",
        "> **Authorization required:** only test systems you have "
        "written authorization to test. This skill describes the "
        "vulnerability pattern. It contains no live payload, no exact "
        "exploit code, and no target URL.",
        "",
        "## What this technique is",
        "",
        *summary,
        "",
        "## Technique pattern",
        "",
        _class_pattern(vuln_class),
        "",
        "## What to look for",
        "",
        "Study the general flow, not a specific target. Look for where "
        "untrusted input enters the system, which validation or "
        "allowlist sits in between, and which sink or decision the "
        "input can reach. Confirm every candidate in your own lab "
        "before treating it as a finding.",
        "",
        "## References",
        "",
        f"- Canonical writeup: {writeup.canonical_url}",
    ]
    if cwe:
        cwe_num = cwe.upper().removeprefix("CWE-")
        lines.append(
            f"- {cwe}: https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        )
    if cve:
        lines.append(f"- {cve}: https://nvd.nist.gov/vuln/detail/{cve}")
    lines += ["", _safe_practice_section()]
    return "\n".join(lines)


def get_registry_skill() -> str:
    """Registry skill: how to call REST/MCP, Lookup #1 vs #2, token limits."""
    name = "writeup-registry"
    description = (
        "How to query the Eunoia writeup registry over REST or MCP. "
        "Only test systems you have written authorization to test. "
        "The registry returns metadata plus links, never full text."
    )
    lines = [
        _frontmatter(name, description),
        "",
        "# Eunoia writeup registry",
        "",
        "> **Authorization required:** only test systems you have "
        "written authorization to test. Reading a writeup is not "
        "permission to test a target.",
        "",
        "## Calling the registry",
        "",
        "REST base is `/v1`. Search with `GET /v1/search`, fetch one "
        "writeup with `GET /v1/writeups/{id}`, fetch its skill with "
        "`GET /v1/writeups/{id}/skill.md`, and check source health with "
        "`GET /v1/status`. Anonymous callers get 60 requests per minute "
        "and keyword search only; an API key raises the limit to 600 "
        "requests per minute and unlocks semantic and hybrid search.",
        "",
        "Over MCP, use `search_writeups` to find candidates, `get_writeup` "
        "for one selected writeup, and `get_writeup_skill` for one "
        "technique you have decided to study in depth. "
        "`list_vuln_classes` and `list_programs` browse the corpus; "
        "`check_freshness` reports how current the index is.",
        "",
        "## Lookup #1 vs Lookup #2",
        "",
        "Lookup #1 runs after recon, before the attack plan: query once "
        "per technology in the target stack, limit 5 per technology, "
        "about 1000 to 1500 tokens per query. Lookup #2 runs mid-test, "
        "only when stuck or when a candidate needs verification: limit 3, "
        "at most 2 re-queries per hypothesis. Never use limit 20 inside "
        "the loop.",
        "",
        "## Token limits",
        "",
        "A search result list is the cheapest layer: one short object "
        "per result, excerpt at most 300 characters. A full writeup "
        "object is only for one selected writeup. A SKILL.md is only "
        "for one technique you will execute, under 5000 tokens. Full "
        "text of the original article never enters the context: follow "
        "the canonical link instead.",
        "",
        "Track seen writeup ids per run and never fetch the same id "
        "twice. After 3 probes with no new signal, stop and re-query "
        "once, then mark the hypothesis debunked.",
        "",
        _safe_practice_section(),
    ]
    return "\n".join(lines)


def get_vuln_class_skill(vuln_class: str,
                         session: Session | None = None) -> str:
    """Aggregate skill for one vuln class, from its best verified writeups.

    Only classes with real data return a skill; an empty class raises
    ``ValueError`` instead of serving an empty aggregate.
    """
    own_session = session is None
    if own_session:
        session = _own_session()
    assert session is not None
    try:
        rows = session.execute(
            select(Writeup, WriteupVuln)
            .join(WriteupVuln, WriteupVuln.writeup_id == Writeup.id)
            .where(WriteupVuln.vuln_class.ilike(vuln_class.strip()))
            .where(Writeup.status == "active")
            .order_by(
                WriteupVuln.bounty_verified.desc(),
                Writeup.published_at.desc().nulls_last(),
            )
            .limit(5)
        ).all()
        if not rows:
            raise ValueError(f"no writeups in vuln class: {vuln_class!r}")
        return _render_class_skill(vuln_class, rows)
    finally:
        if own_session:
            session.close()


def _render_class_skill(vuln_class: str, rows: list) -> str:
    class_slug = _slugify(vuln_class)
    name = f"{class_slug}-fundamentals"
    description = (
        f"Fundamentals of {vuln_class}, from the best verified writeups "
        "in the registry. Only test systems you have written "
        "authorization to test. Patterns only, never a live payload."
    )
    lines = [
        _frontmatter(name, description),
        "",
        f"# {vuln_class} fundamentals",
        "",
        "> **Authorization required:** only test systems you have "
        "written authorization to test. This skill describes the "
        "vulnerability pattern. It contains no live payload, no exact "
        "exploit code, and no target URL.",
        "",
        "## Technique pattern",
        "",
        _class_pattern(vuln_class),
        "",
        "## Best verified writeups",
        "",
    ]
    cwes: list[str] = []
    for writeup, vuln in rows:
        program = f" ({vuln.program})" if vuln.program else ""
        lines.append(f"- [{writeup.title}]({writeup.canonical_url}){program}")
        if vuln.cwe_id and vuln.cwe_id not in cwes:
            cwes.append(vuln.cwe_id)
    lines += ["", "## References", ""]
    for cwe in cwes:
        cwe_num = cwe.upper().removeprefix("CWE-")
        lines.append(
            f"- {cwe}: https://cwe.mitre.org/data/definitions/{cwe_num}.html"
        )
    lines += ["", _safe_practice_section()]
    return "\n".join(lines)
