"""Hybrid search (spec §5.9, §5.8 loop).

Pipeline: structured filter → BM25 top-100 + ANN top-100 in parallel →
RRF (k=60) → top-50 → cross-encoder rerank (OFF by default in MVP,
flag only) → evidence ranking (§5.9) → top-N.

Hard rules enforced here (spec §5.9, Review Focus 4):

* every result carries a ``verified``/``unverified`` label — never a
  bare score;
* ``stack_match == 0`` is excluded from pre-test results, but allowed
  in mid-test semantic search;
* ``limit`` is clamped to 10 server-side;
* non-English writeups (``language`` set and not ``"en"``) are excluded
  from ranking; retracted/takedown/duplicate rows are never served;
* dedup happens before ranking: one row per writeup, however many vuln
  rows or sources it has.

The ``Technique:`` slot of the embedding template is always empty for
DB rows (Task 8: the schema stores no technique summary), so search
never depends on it — technique similarity comes from the embedding of
the title/class/CWE/program/excerpt text that is actually stored.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from eunoia.classify import classify_java_spring, load_aliases_from_csv
from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.embed import MODEL_NAME, MODEL_VERSION, get_model
from eunoia.models import CveCache, Embedding, Writeup, WriteupVuln
from eunoia.ranking import (
    ScoreComponents,
    breakdown_mid_test,
    breakdown_pre_test,
    normalize_exploited,
    normalize_recency,
    normalize_severity,
    normalize_verified,
    rank_mid_test,
    rank_pre_test,
    score_mid_test,
    score_pre_test,
)

__all__ = ["MAX_LIMIT", "SearchResult", "StructuredQuery", "search"]

MAX_LIMIT = 10
_RRF_K = 60
_RETRIEVAL_TOP_N = 100
_RERANK_TOP_N = 50

_VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")
_TOKEN_RE = re.compile(r"[a-z0-9]+")

# Ecosystem groups from the tech-alias seed (all four MVP technologies
# are Maven/Java). Two technologies in the same ecosystem are the same
# "family" for stack_match 0.2; anything without a seed alias has no
# family in MVP.
_ALIASES = load_aliases_from_csv()
_TECH_BY_NAME = {a.technology: a for a in _ALIASES}
_CPE_PRODUCT_TO_TECH = {}
for _alias in _ALIASES:
    if _alias.cpe:
        _parts = _alias.cpe.split(":")
        if len(_parts) >= 6:
            _CPE_PRODUCT_TO_TECH[_parts[4]] = _alias.technology


@dataclass(frozen=True)
class StructuredQuery:
    """One stack-conditioned query (§5.8): one per main technology."""

    tech: tuple[str, ...] = ()
    version: str | None = None
    vuln_class: str | None = None
    cwe: str | None = None
    cve: str | None = None
    endpoint_pattern: str | None = None
    evidence_pattern: str | None = None
    mode: str = "pre_test"

    @classmethod
    def from_query(cls, query: Any) -> "StructuredQuery":
        """Accept a dict (the brief's shape) or an existing instance."""
        if isinstance(query, StructuredQuery):
            return query
        if not isinstance(query, dict):
            raise TypeError("query must be a dict or StructuredQuery")
        tech = query.get("tech") or ()
        if isinstance(tech, str):
            tech = (tech,)
        mode = str(query.get("mode") or "pre_test").lower().replace("-", "_")
        if mode not in ("pre_test", "mid_test"):
            raise ValueError(f"unknown search mode: {mode!r}")
        return cls(
            tech=tuple(str(t).lower() for t in tech),
            version=query.get("version"),
            vuln_class=query.get("vuln_class"),
            cwe=query.get("cwe"),
            cve=query.get("cve"),
            endpoint_pattern=query.get("endpoint_pattern"),
            evidence_pattern=query.get("evidence_pattern"),
            mode=mode,
        )


@dataclass
class SearchResult:
    """One ranked writeup. ``verified`` is True only for
    platform-verified; ``verified_label`` is always one of the three
    tiers, so a result is never shown without a label."""

    writeup_id: str
    title: str
    score: float
    score_breakdown: dict
    match_reason: str
    verified: bool
    verified_label: str
    fetched_at: datetime | None
    indexed_at: datetime | None
    freshness: dict
    flags: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Retrieval helpers
# ---------------------------------------------------------------------------


def _tokenize(text: str | None) -> list[str]:
    if not text:
        return []
    return _TOKEN_RE.findall(text.lower())


def _bm25_scores(
    docs: list[list[str]], terms: list[str], k1: float = 1.5, b: float = 0.75
) -> list[float]:
    """Standard BM25 over tokenized documents. Empty corpus → []."""
    if not docs or not terms:
        return [0.0] * len(docs)
    n = len(docs)
    avgdl = sum(len(d) for d in docs) / n
    df: dict[str, int] = {}
    for doc in docs:
        for term in set(doc):
            df[term] = df.get(term, 0) + 1
    scores = [0.0] * n
    for term in set(terms):
        term_df = df.get(term, 0)
        if term_df == 0:
            continue
        idf = math.log(1.0 + (n - term_df + 0.5) / (term_df + 0.5))
        for i, doc in enumerate(docs):
            tf = doc.count(term)
            if tf == 0:
                continue
            denom = tf + k1 * (1.0 - b + b * len(doc) / avgdl)
            scores[i] += idf * tf * (k1 + 1.0) / denom
    return scores


def _rrf(ranks: list[list[Any]], k: int = _RRF_K) -> dict[Any, float]:
    """Reciprocal rank fusion over 1-based ranked id lists."""
    fused: dict[Any, float] = {}
    for ranked in ranks:
        for rank, item in enumerate(ranked, start=1):
            fused[item] = fused.get(item, 0.0) + 1.0 / (k + rank)
    return fused


def _cosine(a: list[float], b: list[float]) -> float:
    """Cosine similarity clamped to [0, 1]; 0 when either vector is 0."""
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0.0 or nb == 0.0:
        return 0.0
    return max(0.0, min(1.0, dot / (na * nb)))


# ---------------------------------------------------------------------------
# stack_match
# ---------------------------------------------------------------------------


def _version_near_mention(text: str, phrase: str) -> str | None:
    """Version written near a technology mention, e.g. 'Tomcat 10.1.0'."""
    idx = text.lower().find(phrase.lower())
    if idx < 0:
        return None
    window = text[max(0, idx - 10): idx + len(phrase) + 50]
    match = _VERSION_RE.search(window)
    return match.group(0) if match else None


def _stack_match(
    query: StructuredQuery, writeup: Writeup, vuln: WriteupVuln | None
) -> tuple[float, str]:
    """Score 0–1 of a writeup against the target stack (§5.9 table).

    1.0 exact product + version; 0.7 product, target version unknown;
    0.4 product, version differs/unknown on the writeup side; 0.2 same
    family (same ecosystem, different product); 0.0 no relation. With
    no tech in the query there is no stack constraint, so the component
    passes vacuously at 1.0.
    """
    if not query.tech:
        return 1.0, "no stack filter"
    fields = {
        "title": writeup.title or "",
        "excerpt": writeup.excerpt or "",
        "program": vuln.program if vuln and vuln.program else "",
    }
    text = " ".join(fields.values())
    classification = classify_java_spring(fields)
    # Version per seed technology, from the version-filled CPEs.
    cpe_version: dict[str, str | None] = {}
    for cpe in classification.cpe:
        parts = cpe.split(":")
        if len(parts) >= 6:
            tech = _CPE_PRODUCT_TO_TECH.get(parts[4])
            if tech:
                cpe_version[tech] = None if parts[5] == "*" else parts[5]
    best = 0.0
    best_reason = "no stack relation"
    for tech in query.tech:
        alias = _TECH_BY_NAME.get(tech)
        matched = tech in classification.tech
        writeup_version = cpe_version.get(tech) if matched else None
        if not matched:
            # Arbitrary (non-seed) technology: word-boundary text match.
            variants = {tech, tech.replace("-", " ")}
            if any(
                re.search(rf"(?<![\w.]){re.escape(v)}(?![\w])", text.lower())
                for v in variants
            ):
                matched = True
                writeup_version = _version_near_mention(text, tech)
        if matched:
            if query.version is None:
                score, reason = 0.7, "same product, version not exactly known"
            elif writeup_version is None:
                score, reason = 0.4, "same product, version unknown"
            elif writeup_version == query.version:
                score, reason = (
                    1.0,
                    f"exact stack match ({tech} {query.version})",
                )
            else:
                score, reason = (
                    0.4,
                    f"same product, version differs "
                    f"(writeup: {writeup_version})",
                )
        elif alias is not None and classification.tech and any(
            _TECH_BY_NAME.get(t) is not None
            and _TECH_BY_NAME[t].ecosystem == alias.ecosystem
            for t in classification.tech
        ):
            score, reason = 0.2, "same family (Java)"
        else:
            score, reason = 0.0, "no stack relation"
        if score > best:
            best, best_reason = score, reason
    return best, best_reason


# ---------------------------------------------------------------------------
# Freshness / match reason
# ---------------------------------------------------------------------------


def _freshness(age_days: float | None) -> dict:
    """Age label on the recency half-life (180 days)."""
    if age_days is None:
        return {"age_days": None, "label": "unknown"}
    days = int(age_days)
    if days < 180:
        label = "recent"
    elif days < 540:
        label = "aging"
    else:
        label = "old"
    return {"age_days": days, "label": label}


def _match_reason(
    stack_reason: str,
    components: ScoreComponents,
    vuln: WriteupVuln | None,
) -> str:
    parts = [stack_reason]
    if components.technique_similarity >= 0.3 and vuln is not None:
        technique = vuln.vuln_class or "unknown class"
        cwe = vuln.cwe_id or "no CWE"
        parts.append(f"technique similar: {technique} ({cwe})")
    if components.exploited == 1.0:
        parts.append("in CISA KEV")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# search()
# ---------------------------------------------------------------------------


def search(
    query: Any,
    limit: int = 5,
    session: Session | None = None,
    model=None,
    rerank: bool = False,
    retrieval: str = "hybrid",
) -> list[SearchResult]:
    """Hybrid search over the registry. See the module docstring.

    ``retrieval`` selects the retrieval channels: ``"hybrid"`` (BM25 +
    ANN, default), ``"keyword"`` (BM25 only — the anon tier never
    touches the embedding model), or ``"semantic"`` (ANN only).
    """
    structured = StructuredQuery.from_query(query)
    limit = max(1, min(int(limit), MAX_LIMIT))
    if rerank:
        raise NotImplementedError(
            "cross-encoder rerank is not implemented in MVP; "
            "rerank=False only"
        )
    if retrieval not in ("keyword", "semantic", "hybrid"):
        raise ValueError(f"unknown retrieval mode: {retrieval!r}")

    own_session = session is None
    if own_session:
        session = Session(get_engine(get_settings()))
    assert session is not None
    try:
        # --- structured filter -------------------------------------------
        stmt = (
            select(Writeup)
            .outerjoin(
                WriteupVuln, WriteupVuln.writeup_id == Writeup.id
            )
            .where(Writeup.status == "active")
            .where(
                or_(Writeup.language.is_(None), Writeup.language == "en")
            )
        )
        if structured.vuln_class:
            stmt = stmt.where(
                WriteupVuln.vuln_class == structured.vuln_class
            )
        if structured.cwe:
            stmt = stmt.where(
                WriteupVuln.cwe_id == structured.cwe.upper()
            )
        if structured.cve:
            stmt = stmt.where(
                WriteupVuln.cve_id == structured.cve.upper()
            )
        rows = session.execute(stmt).scalars().all()
        # Dedup before ranking: one candidate per writeup.
        candidates: dict[Any, Writeup] = {w.id: w for w in rows}
        if not candidates:
            return []
        ids = list(candidates)

        vuln_rows = (
            session.execute(
                select(WriteupVuln).where(WriteupVuln.writeup_id.in_(ids))
            )
            .scalars()
            .all()
        )
        vulns_by_writeup: dict[Any, list[WriteupVuln]] = {}
        for row in vuln_rows:
            vulns_by_writeup.setdefault(row.writeup_id, []).append(row)

        # --- query terms (BM25) ------------------------------------------
        terms: list[str] = []
        for tech in structured.tech:
            terms.extend(_tokenize(tech))
        terms.extend(_tokenize(structured.vuln_class))
        terms.extend(_tokenize(structured.cwe))
        terms.extend(_tokenize(structured.cve))
        terms.extend(_tokenize(structured.endpoint_pattern))
        terms.extend(_tokenize(structured.evidence_pattern))
        if not terms:
            return []

        docs: list[list[str]] = []
        bm25_ranked: list = []
        if retrieval != "semantic":
            for wid in ids:
                w = candidates[wid]
                vuln = vulns_by_writeup.get(wid, [None])[0]
                docs.append(
                    _tokenize(
                        " ".join(
                            filter(
                                None,
                                [
                                    w.title,
                                    w.excerpt,
                                    vuln.vuln_class if vuln else None,
                                    vuln.cwe_id if vuln else None,
                                    vuln.cve_id if vuln else None,
                                    vuln.program if vuln else None,
                                ],
                            )
                        )
                    )
                )
            bm25 = _bm25_scores(docs, terms)
            bm25_ranked = [
                wid
                for wid, score in sorted(
                    zip(ids, bm25), key=lambda pair: pair[1], reverse=True
                )
                if score > 0
            ][:_RETRIEVAL_TOP_N]

        # --- ANN top-100 ---------------------------------------------------
        ann_ranked: list = []
        ann_similarity: dict = {}
        if retrieval != "keyword":
            query_text = " ".join(
                part
                for part in [
                    " ".join(structured.tech),
                    structured.version or "",
                    structured.vuln_class or "",
                    structured.cwe or "",
                    structured.cve or "",
                    structured.endpoint_pattern or "",
                    structured.evidence_pattern or "",
                ]
                if part
            )
            encoder = model if model is not None else get_model()
            query_vector = [float(v) for v in encoder.encode([query_text])[0]]
            ann_rows = (
                session.execute(
                    select(
                        Embedding.writeup_id,
                        Embedding.embedding.cosine_distance(query_vector).label(
                            "distance"
                        ),
                    )
                    .where(Embedding.writeup_id.in_(ids))
                    .where(Embedding.model == MODEL_NAME)
                    .where(Embedding.model_version == MODEL_VERSION)
                    .order_by("distance")
                    .limit(_RETRIEVAL_TOP_N)
                )
                .all()
            )
            ann_ranked = [row.writeup_id for row in ann_rows]
            ann_similarity = {
                row.writeup_id: max(0.0, min(1.0, 1.0 - float(row.distance)))
                for row in ann_rows
            }

        # --- RRF fusion → top-50 ------------------------------------------
        fused = _rrf([bm25_ranked, ann_ranked])
        shortlist = [
            wid
            for wid, _ in sorted(
                fused.items(), key=lambda pair: pair[1], reverse=True
            )
        ][:_RERANK_TOP_N]
        if not shortlist:
            return []

        # --- evidence components -------------------------------------------
        cve_ids = {
            row.cve_id for rows in vulns_by_writeup.values() for row in rows
        } - {None}
        kev_rows = (
            session.execute(
                select(CveCache).where(CveCache.cve_id.in_(cve_ids))
            )
            .scalars()
            .all()
            if cve_ids
            else []
        )
        kev_by_cve = {row.cve_id: row for row in kev_rows}
        now = datetime.now(timezone.utc)

        results: list[SearchResult] = []
        for wid in shortlist:
            w = candidates[wid]
            vuln_list = vulns_by_writeup.get(wid, [])
            vuln = vuln_list[0] if vuln_list else None

            stack_score, stack_reason = _stack_match(structured, w, vuln)

            exploited = 0.0
            for row in vuln_list:
                if row.cve_id and row.cve_id in kev_by_cve:
                    cached = kev_by_cve[row.cve_id]
                    exploited = max(
                        exploited,
                        normalize_exploited(
                            bool(cached.kev),
                            float(cached.epss)
                            if cached.epss is not None
                            else None,
                        ),
                    )

            severity = 0.0
            severity_missing = True
            for row in vuln_list:
                value, missing = normalize_severity(
                    float(row.cvss_score)
                    if row.cvss_score is not None
                    else None,
                    row.severity,
                )
                severity = max(severity, value)
                severity_missing = severity_missing and missing

            ref_date = w.disclosed_at or w.published_at or w.fetched_at
            age_days = (
                (now - ref_date).total_seconds() / 86400.0
                if ref_date is not None
                else None
            )
            recency = normalize_recency(age_days)

            verified_score, verified_label = 0.0, "unverified"
            for row in vuln_list:
                value, label = normalize_verified(
                    bool(row.bounty_verified),
                    float(row.bounty_amount)
                    if row.bounty_amount is not None
                    else None,
                    row.severity_source,
                    has_severity=row.severity is not None,
                )
                if value > verified_score:
                    verified_score, verified_label = value, label

            technique = (
                ann_similarity.get(wid, 0.0)
                if structured.mode == "mid_test"
                else 0.0
            )
            components = ScoreComponents(
                stack_match=stack_score,
                exploited=exploited,
                severity=severity,
                recency=recency,
                verified=verified_score,
                technique_similarity=technique,
            )
            if structured.mode == "mid_test":
                score = score_mid_test(components)
                breakdown = breakdown_mid_test(components)
            else:
                score = score_pre_test(components)
                breakdown = breakdown_pre_test(components)

            flags: list[str] = []
            if severity_missing:
                flags.append("severity_unknown")
            if age_days is None:
                flags.append("date_unknown")

            results.append(
                SearchResult(
                    writeup_id=w.api_id,
                    title=w.title,
                    score=score,
                    score_breakdown=breakdown,
                    match_reason=_match_reason(
                        stack_reason, components, vuln
                    ),
                    verified=verified_score == 1.0,
                    verified_label=verified_label,
                    fetched_at=w.fetched_at,
                    indexed_at=w.last_seen_at or w.fetched_at,
                    freshness=_freshness(age_days),
                    flags=flags,
                )
            )

        ranked = (
            rank_mid_test(results)
            if structured.mode == "mid_test"
            else rank_pre_test(results)
        )
        return ranked[:limit]
    finally:
        if own_session:
            session.close()
