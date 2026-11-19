"""Settings: loaded from environment only, never from code.

Secrets rule (plan Global Constraints): the database stores only
``auth_ref`` — a vault key *name*. This module enforces the same rule at
the config boundary: a DATABASE_URL containing a password is rejected,
because a password in config is a secret in the wrong place.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

DEFAULT_DATABASE_URL = "postgresql+psycopg://eunoia@localhost:5432/eunoia"
DEFAULT_HACKERONE_TOKEN_REF = "hackerone/api-token"
DEFAULT_NVD_API_KEY_REF = "nvd/api-key"


def _reject_password_in_url(url: str) -> None:
    if urlparse(url).password:
        raise ValueError(
            "DATABASE_URL must not contain a password; "
            "use trust/peer auth locally or a vault-managed credential"
        )


@dataclass(frozen=True)
class Settings:
    DATABASE_URL: str
    HACKERONE_TOKEN_REF: str
    NVD_API_KEY_REF: str


def get_settings(
    DATABASE_URL: str | None = None,
    HACKERONE_TOKEN_REF: str | None = None,
    NVD_API_KEY_REF: str | None = None,
) -> Settings:
    """Build settings from explicit args, else environment, else defaults.

    Explicit kwargs win over env vars so tests can pass values directly.
    """
    db_url = DATABASE_URL or os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
    _reject_password_in_url(db_url)
    return Settings(
        DATABASE_URL=db_url,
        HACKERONE_TOKEN_REF=HACKERONE_TOKEN_REF
        or os.environ.get("HACKERONE_TOKEN_REF", DEFAULT_HACKERONE_TOKEN_REF),
        NVD_API_KEY_REF=NVD_API_KEY_REF
        or os.environ.get("NVD_API_KEY_REF", DEFAULT_NVD_API_KEY_REF),
    )
