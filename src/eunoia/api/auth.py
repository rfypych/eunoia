"""API-key auth (spec §5.5, Task 10).

Keys live in ``api_keys`` as SHA-256 hashes only; the plaintext is
shown once at creation and never stored. A key is per-agent/owner,
revocable, and carries a tier (``free`` in v1). Anonymous callers have
no key and get the anon tier.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from eunoia.models import ApiKey

_KEY_PREFIX = "eun_"

__all__ = ["create_api_key", "revoke_api_key", "verify_api_key"]


def _hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def create_api_key(
    session: Session, *, owner: str | None = None, tier: str = "free"
) -> tuple[str, ApiKey]:
    """Create a key; returns ``(plaintext, row)``.

    The plaintext is returned only here — the row stores the hash, so
    it can never be recovered from the database afterwards.
    """
    plaintext = _KEY_PREFIX + secrets.token_urlsafe(32)
    row = ApiKey(key_hash=_hash_key(plaintext), owner=owner, tier=tier)
    session.add(row)
    session.flush()
    return plaintext, row


def verify_api_key(session: Session, plaintext: str) -> ApiKey | None:
    """Return the live key row for a presented key, else None.

    A revoked key verifies as nothing. ``last_used_at`` is bumped on
    success (flush only; the caller owns the transaction).
    """
    if not plaintext or not plaintext.startswith(_KEY_PREFIX):
        return None
    row = (
        session.query(ApiKey)
        .filter_by(key_hash=_hash_key(plaintext))
        .first()
    )
    if row is None or row.revoked:
        return None
    row.last_used_at = datetime.now(timezone.utc)
    session.flush()
    return row


def revoke_api_key(session: Session, key_id: uuid.UUID) -> bool:
    """Revoke a key by id; False when the id does not exist."""
    row = session.get(ApiKey, key_id)
    if row is None:
        return False
    row.revoked = True
    row.revoked_at = datetime.now(timezone.utc)
    session.flush()
    return True
