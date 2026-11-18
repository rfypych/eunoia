"""llms.txt renderer (spec §5.11).

The registry serves one small ``llms.txt`` index: H1, a one-line
summary with scope and a safety line, then H2 sections API / Browse /
Top writeups / Policies / Optional. There is no full-text dump file;
agents fetch full content through the API or MCP, one writeup at a
time.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.models import Writeup, WriteupVuln
from eunoia.safety.serving import servable_filter

TOP_WRITEUPS = 10


def _own_session() -> Session:
    return Session(get_engine(get_settings()))


def _dedupe_writeups(writeups: list[Writeup]) -> list[Writeup]:
    """One entry per writeup id, first occurrence wins (a writeup with
    several vuln rows joins once per row — Task 12 triage item)."""
    seen: set = set()
    out: list[Writeup] = []
    for writeup in writeups:
        if writeup.id not in seen:
            seen.add(writeup.id)
            out.append(writeup)
    return out


def _top_writeups(session: Session) -> list[Writeup]:
    """Top servable writeups: verified-bounty first, then most recent.

    Final review I2: the shared serving gate applies here — only
    ``status in (active, updated)`` and not quality-quarantined rows
    appear, and each writeup appears once even with several vuln rows.
    """
    verified = session.execute(
        select(Writeup)
        .join(WriteupVuln, WriteupVuln.writeup_id == Writeup.id)
        .where(*servable_filter())
        .where(WriteupVuln.bounty_verified.is_(True))
        .order_by(Writeup.published_at.desc().nulls_last())
        .limit(TOP_WRITEUPS)
    ).scalars().all()
    verified = _dedupe_writeups(verified)
    seen = {w.id for w in verified}
    if len(verified) < TOP_WRITEUPS:
        recent = session.execute(
            select(Writeup)
            .where(*servable_filter())
            .order_by(Writeup.published_at.desc().nulls_last())
            .limit(TOP_WRITEUPS)
        ).scalars().all()
        verified += [w for w in recent if w.id not in seen]
    return verified[:TOP_WRITEUPS]


def render_llms_txt(session: Session | None = None) -> str:
    """Render the registry ``llms.txt`` index."""
    own_session = session is None
    if own_session:
        session = _own_session()
    assert session is not None
    try:
        top = _top_writeups(session)
    finally:
        if own_session:
            session.close()

    lines = [
        "# Eunoia — Pentest Writeup Registry",
        "",
        "> Eunoia indexes authorized public bug-bounty writeups for Java "
        "and Spring targets as metadata plus links, never full text. "
        "Only test systems you have written authorization to test.",
        "",
        "## API",
        "",
        "- Search: `GET /v1/search` (keyword, semantic, hybrid).",
        "- One writeup: `GET /v1/writeups/{id}`.",
        "- Skill for one writeup: `GET /v1/writeups/{id}/skill.md`.",
        "- Source health: `GET /v1/status`.",
        "- Anonymous: 60 requests per minute, keyword search only. "
        "API key: 600 requests per minute, semantic and hybrid search.",
        "",
        "## Browse",
        "",
        "- `GET /v1/vuln-classes` — vulnerability classes in the corpus.",
        "- `GET /v1/programs` — bounty programs in the corpus.",
        "- `GET /v1/authors` — writeup authors in the corpus.",
        "",
        "## Top writeups",
        "",
    ]
    if top:
        for writeup in top:
            lines.append(f"- [{writeup.title}]({writeup.canonical_url})")
    else:
        lines.append("No writeups indexed yet.")
    lines += [
        "",
        "## Policies",
        "",
        "- Scope: the registry only indexes authorized public "
        "disclosures, vendor advisories, and researcher writeups from "
        "testing under program rules or in a lab.",
        "- Authorization: reading a writeup is not permission to test "
        "a target. Only test systems you have written authorization "
        "to test.",
        "- Content: skills and excerpts describe vulnerability "
        "patterns only. No live payloads, no exact exploit code, no "
        "target URLs outside the canonical links.",
        "- Takedown: a disclosure that is retracted or taken down is "
        "removed from serving and kept only as a stub.",
        "",
        "## Optional",
        "",
        "- MCP server (read-only): `search_writeups`, `get_writeup`, "
        "`get_writeup_skill`, `list_vuln_classes`, `list_programs`, "
        "`check_freshness`.",
        "- Per-writeup SKILL.md resources are available at "
        "`/v1/writeups/{id}/skill.md`, one technique at a time.",
        "- Full text of the original article is only at the canonical "
        "link; it never enters the agent context.",
        "",
    ]
    return "\n".join(lines)
