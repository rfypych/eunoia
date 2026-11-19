"""Task 8: Embeddings (template string, halfvec, HNSW) (spec §5.7).

The embedding model is injected (a stub in these tests) so no test ever
downloads a model or hits the network. DB tests run against the dedicated
``eunoia_test`` database (same fixture pattern as tests/test_enrich.py).
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from eunoia.config import get_settings
from eunoia.db import get_engine
from eunoia.dedup import content_hash
from eunoia.embed import (
    MODEL_NAME,
    MODEL_VERSION,
    embed_writeup,
    embedded_text,
)
from eunoia.models import Base, Embedding, Writeup, WriteupVuln

TEST_DATABASE_URL = "postgresql://eunoia@localhost:5432/eunoia_test"


@pytest.fixture()
def session():
    engine = get_engine(get_settings(DATABASE_URL=TEST_DATABASE_URL))
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except OperationalError:
        pytest.fail(
            "Test database 'eunoia_test' is missing or unreachable. "
            "Create it with: bash scripts/setup_test_db.sh"
        )
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
        s.rollback()
    Base.metadata.drop_all(engine)


class StubModel:
    """Deterministic 384-dim encoder: no weights, no network."""

    def __init__(self, value: float = 0.5):
        self.value = value
        self.calls: list[str] = []

    def encode(self, texts):
        if isinstance(texts, str):
            texts = [texts]
        self.calls.extend(texts)
        return [[self.value] * 384 for _ in texts]


def _make_writeup(session, title="SSRF on profile API", **overrides):
    writeup = Writeup(
        id=uuid.uuid4(),
        canonical_url=overrides.pop(
            "canonical_url", f"https://example.com/{uuid.uuid4().hex[:8]}"
        ),
        url_hash=uuid.uuid4().hex,
        title=title,
        excerpt=overrides.pop("excerpt", "An SSRF in the profile endpoint."),
        content_hash=overrides.pop("content_hash", "abc123"),
    )
    session.add(writeup)
    session.add(
        WriteupVuln(
            writeup_id=writeup.id,
            vuln_class=overrides.pop("vuln_class", "SSRF"),
            cwe_id=overrides.pop("cwe_id", "CWE-918"),
            program=overrides.pop("program", "Example Corp"),
        )
    )
    session.commit()
    return writeup


# --- template ---------------------------------------------------------------


def test_embed_template_uses_metadata_not_html():
    t = embedded_text({"title": "SSRF", "vuln_class": "SSRF", "cwe": "CWE-918", "program": "x", "excerpt": "e", "technique": "pdf parser"})
    assert "SSRF" in t and "<html" not in t


def test_embed_template_exact_format():
    t = embedded_text(
        {
            "title": "SSRF",
            "vuln_class": "SSRF",
            "cwe": "CWE-918",
            "program": "x",
            "excerpt": "e",
            "technique": "pdf parser",
        }
    )
    assert t == "SSRF. SSRF (CWE-918). Target: x. e Technique: pdf parser"


def test_embed_template_missing_fields_never_prints_none():
    t = embedded_text({"title": "SSRF"})
    assert "None" not in t
    assert t.startswith("SSRF. ")


# --- embed_writeup ----------------------------------------------------------


def test_embed_writeup_stores_halfvec_row(session):
    writeup = _make_writeup(session)
    result = embed_writeup(writeup.id, session=session, model=StubModel())
    assert result == "embedded"
    row = (
        session.query(Embedding)
        .filter_by(writeup_id=writeup.id, model=MODEL_NAME)
        .one()
    )
    assert row.model_version == MODEL_VERSION
    assert row.embedding is not None and len(row.embedding) == 384
    assert row.embedded_text_hash == content_hash(
        embedded_text(
            {
                "title": writeup.title,
                "vuln_class": "SSRF",
                "cwe": "CWE-918",
                "program": "Example Corp",
                "excerpt": writeup.excerpt,
                "technique": "",
            }
        )
    )


def test_no_reembed_when_hash_unchanged(session):
    writeup = _make_writeup(session)
    model = StubModel()
    embed_writeup(writeup.id, session=session, model=model)
    assert embed_writeup(writeup.id, session=session, model=model) == "skipped"
    assert (
        session.query(Embedding).filter_by(writeup_id=writeup.id).count() == 1
    )
    assert len(model.calls) == 1  # the encoder ran exactly once


def test_reembed_when_content_changes(session):
    writeup = _make_writeup(session)
    model = StubModel()
    embed_writeup(writeup.id, session=session, model=model)
    writeup.title = "SSRF on avatar upload"
    writeup.excerpt = "A different SSRF, same program."
    session.commit()
    assert embed_writeup(writeup.id, session=session, model=model) == "embedded"
    assert (
        session.query(Embedding).filter_by(writeup_id=writeup.id).count() == 1
    )
    assert len(model.calls) == 2


def test_model_change_creates_versioned_row_not_silent_mix(session):
    writeup = _make_writeup(session)
    embed_writeup(writeup.id, session=session, model=StubModel())
    # A new model version re-embeds into its own row; the old row stays.
    result = embed_writeup(
        writeup.id,
        session=session,
        model=StubModel(value=0.25),
        model_name=MODEL_NAME,
        model_version="2.0.0",
    )
    assert result == "embedded"
    rows = session.query(Embedding).filter_by(writeup_id=writeup.id).all()
    assert {r.model_version for r in rows} == {MODEL_VERSION, "2.0.0"}
    assert [r.embedding[0] for r in rows if r.model_version == "2.0.0"] == [0.25]


def test_embed_writeup_unknown_id_raises(session):
    with pytest.raises(ValueError, match="unknown writeup"):
        embed_writeup(uuid.uuid4(), session=session, model=StubModel())


# --- HNSW index ---------------------------------------------------------------


def test_hnsw_index_exists_on_embeddings(session):
    row = session.execute(
        text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE tablename = 'embeddings' AND indexname = 'ix_embeddings_embedding_hnsw'"
        )
    ).one()
    indexdef = row[0]
    assert "hnsw" in indexdef
    assert "halfvec_cosine_ops" in indexdef
    assert "m = 16" in indexdef or "m='16'" in indexdef
    assert "ef_construction = 64" in indexdef or "ef_construction='64'" in indexdef
