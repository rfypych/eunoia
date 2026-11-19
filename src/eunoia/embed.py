"""Embeddings (spec §5.7).

The embedded text is a compact metadata template, never raw HTML::

    "{title}. {vuln_class} ({cwe}). Target: {program}. {excerpt} "
    "Technique: {ringkasan teknik}"

Model: ``all-MiniLM-L6-v2`` (384-dim), stored as ``halfvec``. Each row
records ``model`` + ``model_version``; a model change re-embeds into a
new versioned row, never a silent mix with old vectors.

Re-embed rule: embed only when the stored ``embedded_text_hash`` differs
from the hash of the current template text. The hash is
:func:`eunoia.dedup.content_hash` (SHA-256 of the normalized text), so
the skip decision is a pure function of the template text — a change to
the title, class, CWE, program, excerpt, or technique re-embeds; an
unchanged writeup is skipped.

The model is loaded lazily (``sentence-transformers`` + torch are heavy)
and can be injected for tests, so no test ever downloads weights.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import content_hash
from eunoia.models import Embedding, Writeup, WriteupVuln

MODEL_NAME = "all-MiniLM-L6-v2"
MODEL_VERSION = "1.0.0"
EMBEDDING_DIM = 384

_MODEL = None


def _field(writeup: Any, name: str) -> str:
    """Read one template field from a dict or an object; missing → ""."""
    if isinstance(writeup, dict):
        value = writeup.get(name)
    else:
        value = getattr(writeup, name, None)
    return "" if value is None else str(value)


def embedded_text(writeup: Any) -> str:
    """Build the embedding template string for one writeup.

    Accepts a dict (``title``, ``vuln_class``, ``cwe``, ``program``,
    ``excerpt``, ``technique``) or an object with those attributes.
    Missing fields render as empty strings, never as ``"None"``.
    """
    return (
        f"{_field(writeup, 'title')}. "
        f"{_field(writeup, 'vuln_class')} ({_field(writeup, 'cwe')}). "
        f"Target: {_field(writeup, 'program')}. "
        f"{_field(writeup, 'excerpt')} "
        f"Technique: {_field(writeup, 'technique')}"
    )


def get_model():
    """Load (once) the production embedding model."""
    global _MODEL
    if _MODEL is None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:  # pragma: no cover - missing dep
            raise RuntimeError(
                "sentence-transformers is not installed; "
                'run: pip install "eunoia-agents[embed]"'
            ) from exc
        _MODEL = SentenceTransformer(MODEL_NAME)
    return _MODEL


def _writeup_template_dict(writeup: Writeup, vuln: WriteupVuln | None) -> dict:
    """Template fields for a DB writeup + its first vuln row.

    The schema has no stored technique summary, so ``technique`` is
    empty for DB rows; the template's other fields carry the signal.
    """
    return {
        "title": writeup.title,
        "vuln_class": vuln.vuln_class if vuln else None,
        "cwe": vuln.cwe_id if vuln else None,
        "program": vuln.program if vuln else None,
        "excerpt": writeup.excerpt,
        "technique": "",
    }


def embed_writeup(
    writeup_id: uuid.UUID,
    session: Session | None = None,
    model=None,
    model_name: str = MODEL_NAME,
    model_version: str = MODEL_VERSION,
) -> str:
    """Embed one writeup; returns ``"embedded"`` or ``"skipped"``.

    Skips (no encoder call, no new row) when a row for this
    ``(writeup_id, model, model_version)`` already holds the hash of
    the current template text. A model/version change has no such row,
    so it embeds into a new versioned row. Raises ``ValueError`` for an
    unknown writeup id or a vector that is not 384-dim.

    When ``session`` is passed in, this only flushes; the caller owns
    the transaction. Without one, a session is opened, committed, and
    closed here.
    """
    own_session = session is None
    if own_session:
        session = Session(get_engine(get_settings()))
    assert session is not None
    try:
        writeup = session.get(Writeup, writeup_id)
        if writeup is None:
            raise ValueError(f"unknown writeup: {writeup_id}")
        vuln = session.execute(
            select(WriteupVuln)
            .where(WriteupVuln.writeup_id == writeup_id)
            .order_by(WriteupVuln.id)
        ).scalars().first()
        text = embedded_text(_writeup_template_dict(writeup, vuln))
        text_hash = content_hash(text)

        existing = session.execute(
            select(Embedding).where(
                Embedding.writeup_id == writeup_id,
                Embedding.model == model_name,
                Embedding.model_version == model_version,
            )
        ).scalars().first()
        if existing is not None and existing.embedded_text_hash == text_hash:
            return "skipped"

        encoder = model if model is not None else get_model()
        vector = encoder.encode([text])[0]
        embedding = [float(v) for v in vector]
        if len(embedding) != EMBEDDING_DIM:
            raise ValueError(
                f"expected a {EMBEDDING_DIM}-dim vector, got {len(embedding)}"
            )

        if existing is None:
            session.add(
                Embedding(
                    writeup_id=writeup_id,
                    model=model_name,
                    model_version=model_version,
                    embedding=embedding,
                    embedded_text_hash=text_hash,
                )
            )
        else:
            existing.embedding = embedding
            existing.embedded_text_hash = text_hash
        session.flush()
        if own_session:
            session.commit()
        return "embedded"
    finally:
        if own_session:
            session.close()
