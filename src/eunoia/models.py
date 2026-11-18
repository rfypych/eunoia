"""Core schema — spec §5.4 data model (plus ``jobs``/``source_hosts`` from
§5.3/§5.7, and ``run_lessons`` schema only per §7.3).

One model class per table, exact column names from the spec. No business
logic lives here: this module only declares tables, types, and defaults.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime

from pgvector.sqlalchemy import HALFVEC
from sqlalchemy import (
    BigInteger,
    Boolean,
    Date,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

# ---------------------------------------------------------------------------
# UUIDv7 (RFC 9562). Python 3.12 has no uuid.uuid7; the 48-bit unix-ms
# timestamp + version/variant bits + 62 random bits are implemented here
# so writeup ids are time-ordered and match the spec's UUIDv7 requirement.
# ---------------------------------------------------------------------------


def uuid7() -> uuid.UUID:
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms << 80) | (0x7 << 76) | ((rand >> 62) & 0xFFF) << 64
    value |= (0b10 << 62) | (rand & ((1 << 62) - 1))
    return uuid.UUID(int=value)


class Base(DeclarativeBase):
    pass


# Spec §5.4 enums (exact value sets).
SourceType = Enum(
    "hackerone_report", "bugcrowd_disclosure", "research", "blog_writeup",
    "advisory", name="writeup_source_type",
)
WriteupStatus = Enum(
    "active", "updated", "retracted", "takedown", "duplicate_of",
    name="writeup_status",
)
Severity = Enum("none", "low", "medium", "high", "critical", name="severity")
SourceKind = Enum("api", "rss", "bulk", "sitemap", "html", name="source_kind")
WriteupEventType = Enum(
    "created", "updated", "retracted", "takedown", "merged",
    name="writeup_event_type",
)
RunLessonOutcome = Enum(
    "confirmed", "false_positive", "debunked", name="run_lesson_outcome",
)
JobStatus = Enum(
    "pending", "running", "done", "failed", "dead", name="job_status",
)


def _ts() -> DateTime:
    return DateTime(timezone=True)


class Writeup(Base):
    __tablename__ = "writeups"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    canonical_url: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    url_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # Platform external id (e.g. "hackerone:689314") — layer 2 dedup key for
    # persisted rows (migration 0002). Nullable: not every source has one.
    external_id: Mapped[str | None] = mapped_column(String(128), index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    excerpt: Mapped[str | None] = mapped_column(String(300))
    author_name: Mapped[str | None] = mapped_column(Text)
    author_url: Mapped[str | None] = mapped_column(Text)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"))
    source_type: Mapped[str | None] = mapped_column(SourceType)
    published_at: Mapped[datetime | None] = mapped_column(_ts())
    disclosed_at: Mapped[datetime | None] = mapped_column(_ts())
    fetched_at: Mapped[datetime | None] = mapped_column(_ts())
    last_seen_at: Mapped[datetime | None] = mapped_column(_ts())
    content_hash: Mapped[str | None] = mapped_column(String(64))
    simhash: Mapped[int | None] = mapped_column(BigInteger)
    language: Mapped[str | None] = mapped_column(String(10))
    status: Mapped[str] = mapped_column(
        WriteupStatus, nullable=False, server_default="active"
    )
    duplicate_of_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("writeups.id")
    )
    license_note: Mapped[str | None] = mapped_column(Text)
    takedown_at: Mapped[datetime | None] = mapped_column(_ts())
    takedown_reason: Mapped[str | None] = mapped_column(Text)

    @property
    def api_id(self) -> str:
        """Public API id: ``w_...`` (spec §5.4: UUIDv7 PK, shown as w_...)."""
        return f"w_{self.id.hex}"


class WriteupVuln(Base):
    __tablename__ = "writeup_vulns"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    vuln_class: Mapped[str | None] = mapped_column(String(64))
    cwe_id: Mapped[str | None] = mapped_column(String(16))
    cve_id: Mapped[str | None] = mapped_column(String(32))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    severity: Mapped[str | None] = mapped_column(Severity)
    severity_source: Mapped[str | None] = mapped_column(String(64))
    bounty_amount: Mapped[float | None] = mapped_column(Numeric(12, 2))
    bounty_currency: Mapped[str | None] = mapped_column(String(3))
    bounty_verified: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    verified_against: Mapped[str | None] = mapped_column(String(32))
    program: Mapped[str | None] = mapped_column(Text)
    vendor: Mapped[str | None] = mapped_column(Text)
    target: Mapped[str | None] = mapped_column(Text)
    program_slug: Mapped[str | None] = mapped_column(String(128))

    __table_args__ = (
        Index("ix_writeup_vulns_writeup_id", "writeup_id"),
        Index("ix_writeup_vulns_cve_id", "cve_id"),
        Index("ix_writeup_vulns_vuln_class", "vuln_class"),
    )


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str | None] = mapped_column(Text)
    type: Mapped[str | None] = mapped_column(SourceKind)
    base_url: Mapped[str | None] = mapped_column(Text)
    feed_url: Mapped[str | None] = mapped_column(Text)
    poll_interval_s: Mapped[int | None] = mapped_column(BigInteger)
    rate_limit_per_min: Mapped[int | None] = mapped_column(BigInteger)
    # Vault key NAME only — never a secret (plan Global Constraints).
    auth_ref: Mapped[str | None] = mapped_column(Text)
    cursor_state: Mapped[dict | None] = mapped_column(JSONB)
    last_poll_at: Mapped[datetime | None] = mapped_column(_ts())
    last_success_at: Mapped[datetime | None] = mapped_column(_ts())
    consecutive_failures: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="0"
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )


class WriteupSource(Base):
    __tablename__ = "writeup_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"))
    source_url: Mapped[str] = mapped_column(Text, nullable=False)
    first_seen_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("writeup_id", "source_url", name="uq_writeup_source_url"),
    )


class RawCapture(Base):
    __tablename__ = "raw_captures"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    fetched_at: Mapped[datetime | None] = mapped_column(_ts())
    http_status: Mapped[int | None] = mapped_column(BigInteger)
    etag: Mapped[str | None] = mapped_column(Text)
    last_modified: Mapped[str | None] = mapped_column(Text)
    raw_body_ref: Mapped[str | None] = mapped_column(Text)
    extracted_text_hash: Mapped[str | None] = mapped_column(String(64))


class WriteupEvent(Base):
    __tablename__ = "writeup_events"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    event: Mapped[str] = mapped_column(WriteupEventType, nullable=False)
    at: Mapped[datetime | None] = mapped_column(_ts(), server_default=func.now())
    actor: Mapped[str | None] = mapped_column(String(128))
    detail: Mapped[dict | None] = mapped_column(JSONB)


class Embedding(Base):
    __tablename__ = "embeddings"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    model: Mapped[str | None] = mapped_column(String(128))
    model_version: Mapped[str | None] = mapped_column(String(64))
    embedding: Mapped[list[float] | None] = mapped_column(HALFVEC(384))
    embedded_text_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "writeup_id", "model", "model_version",
            name="uq_embedding_writeup_model_version",
        ),
        # HNSW ANN index (spec §5.7, Task 8): cosine distance, m=16,
        # ef_construction=64. Declared here so Base.metadata.create_all
        # (tests) and future autogenerate match migration 0003.
        Index(
            "ix_embeddings_embedding_hnsw",
            "embedding",
            postgresql_using="hnsw",
            postgresql_ops={"embedding": "halfvec_cosine_ops"},
            postgresql_with={"m": 16, "ef_construction": 64},
        ),
    )


class Takedown(Base):
    __tablename__ = "takedowns"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    writeup_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("writeups.id", ondelete="CASCADE"), nullable=False
    )
    requester: Mapped[str | None] = mapped_column(Text)
    notice_ref: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime | None] = mapped_column(_ts())
    action: Mapped[str | None] = mapped_column(Text)
    resolved_at: Mapped[datetime | None] = mapped_column(_ts())
    counter_notice_at: Mapped[datetime | None] = mapped_column(_ts())


class TechAlias(Base):
    __tablename__ = "tech_aliases"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    technology: Mapped[str] = mapped_column(String(128), nullable=False)
    cpe: Mapped[str | None] = mapped_column(Text)
    ecosystem: Mapped[str | None] = mapped_column(String(64))
    package_name: Mapped[str | None] = mapped_column(String(256))
    version_pattern: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("technology", "cpe", name="uq_tech_alias_cpe"),
    )


class CveCache(Base):
    __tablename__ = "cve_cache"

    cve_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    nvd_json: Mapped[dict | None] = mapped_column(JSONB)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(128))
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    kev: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    kev_date_added: Mapped[datetime | None] = mapped_column(Date)
    epss: Mapped[float | None] = mapped_column(Numeric(5, 4))
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(5, 4))
    fetched_at: Mapped[datetime | None] = mapped_column(_ts())
    expires_at: Mapped[datetime | None] = mapped_column(_ts())


class Job(Base):
    """Durable queue (§5.7): ``SELECT ... FOR UPDATE SKIP LOCKED`` workers.

    ``idempotency_key`` is ``source + canonical_url`` or
    ``source + external_id`` (§5.3); workers upsert, never blind-insert.
    Dead-letter after 5 attempts (``max_attempts``), back-off 1m → 1h → 1d.
    """

    __tablename__ = "jobs"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str | None] = mapped_column(ForeignKey("sources.id"))
    idempotency_key: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    payload: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(
        JobStatus, nullable=False, server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(BigInteger, nullable=False, server_default="0")
    max_attempts: Mapped[int] = mapped_column(
        BigInteger, nullable=False, server_default="5"
    )
    next_attempt_at: Mapped[datetime | None] = mapped_column(_ts())
    created_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )
    updated_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now(), onupdate=func.now()
    )
    error: Mapped[str | None] = mapped_column(Text)


class SourceHost(Base):
    """Per-host politeness budget (§5.7): one 429 = back off 60s and halve
    the budget; three 429s in a day = pause the host until tomorrow."""

    __tablename__ = "source_hosts"

    host: Mapped[str] = mapped_column(String(256), primary_key=True)
    min_interval_ms: Mapped[int | None] = mapped_column(BigInteger)
    daily_cap: Mapped[int | None] = mapped_column(BigInteger)
    robots_txt: Mapped[bool | None] = mapped_column(Boolean)
    last_429: Mapped[datetime | None] = mapped_column(_ts())


class RunLesson(Base):
    """Lessons-network foundation (§7.3): schema only in MVP. No MVP code
    writes to this table; the cross-engagement feedback loop is post-MVP."""

    __tablename__ = "run_lessons"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    stack_fingerprint: Mapped[str | None] = mapped_column(String(64))
    technique: Mapped[str | None] = mapped_column(Text)
    writeup_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("writeups.id"))
    outcome: Mapped[str | None] = mapped_column(RunLessonOutcome)
    submitted_by: Mapped[str | None] = mapped_column(String(128))
    submitted_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )


class ApiKey(Base):
    """REST/MCP API keys (spec §5.5, Task 10).

    Only the SHA-256 hash is stored; the plaintext key is shown once
    at creation and never again. Revocation is a flag, never a delete,
    so past usage stays attributable.
    """

    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    owner: Mapped[str | None] = mapped_column(String(256))
    tier: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="free"
    )
    created_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )
    last_used_at: Mapped[datetime | None] = mapped_column(_ts())
    revoked: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    revoked_at: Mapped[datetime | None] = mapped_column(_ts())

    @property
    def api_id(self) -> str:
        return f"key_{self.id.hex}"


class Submission(Base):
    """Human review queue for POST /v1/submissions (spec §5.5).

    A submission is never auto-indexed: it sits in ``in_review`` until
    a human curates it. One in-review row per URL (application-level
    idempotency; re-submitting the same URL returns the existing row).
    """

    __tablename__ = "submissions"

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="in_review"
    )
    submitted_at: Mapped[datetime | None] = mapped_column(
        _ts(), server_default=func.now()
    )

    @property
    def api_id(self) -> str:
        return f"sub_{self.id.hex}"
