"""Task 2: settings load from env only; secrets are never accepted in config."""

import os

import pytest

from eunoia.config import get_settings


def test_settings_reject_secret_in_db_url():
    with pytest.raises(ValueError):
        get_settings(DATABASE_URL="postgres://user:password@db/eunoia")


def test_settings_defaults_have_no_password(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("HACKERONE_TOKEN_REF", raising=False)
    monkeypatch.delenv("NVD_API_KEY_REF", raising=False)
    settings = get_settings()
    assert "password" not in settings.DATABASE_URL
    assert settings.DATABASE_URL.startswith("postgresql+psycopg://")


def test_settings_env_override(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://eunoia@localhost:5432/eunoia")
    monkeypatch.setenv("HACKERONE_TOKEN_REF", "vault/hackerone-token")
    settings = get_settings()
    assert settings.DATABASE_URL == "postgresql+psycopg://eunoia@localhost:5432/eunoia"
    assert settings.HACKERONE_TOKEN_REF == "vault/hackerone-token"


def test_settings_kwargs_override_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://eunoia@localhost:5432/eunoia")
    settings = get_settings(DATABASE_URL="postgresql+psycopg://other@localhost:5432/other")
    assert settings.DATABASE_URL == "postgresql+psycopg://other@localhost:5432/other"
