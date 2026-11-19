"""T1 (Rea-standard): reproducible dev setup + CI.

Meta-tests, no database needed. They pin the contract of the
one-command setup so a future edit cannot silently drop it:

- ``bash scripts/setup_dev.sh`` is the one command: it brings up
  Postgres 16 + pgvector (Docker Compose when available, otherwise
  the local cluster), creates the dev and test databases, runs
  migrations on both, and seeds the dev database.
- ``.github/workflows/ci.yml`` runs the full suite from a clean
  checkout, plus a separate job for the tests that need no DB.
- The README documents the exact commands.
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent
SETUP = _REPO / "scripts" / "setup_dev.sh"
COMPOSE = _REPO / "docker-compose.yml"
CI = _REPO / ".github" / "workflows" / "ci.yml"
README = _REPO / "README.md"

NON_DB_TESTS = [
    "tests/test_config.py",
    "tests/test_dedup.py",
    "tests/test_dod.py",
    "tests/test_probe.py",
    "tests/test_ranking.py",
]


def test_setup_script_exists_and_is_executable():
    assert SETUP.exists(), "scripts/setup_dev.sh is missing"
    assert os.access(SETUP, os.X_OK), "scripts/setup_dev.sh is not executable"


def test_setup_script_covers_both_postgres_backends():
    body = SETUP.read_text()
    assert "docker compose" in body, "setup must use Docker Compose when available"
    assert "pg_ctlcluster" in body, "setup must fall back to the local cluster"
    assert "eunoia_test" in body, "setup must create the test database"
    assert "alembic upgrade head" in body, "setup must run migrations"
    assert "seed_sources" in body, "setup must seed the dev database"


def test_setup_script_checks_pgvector_version():
    body = SETUP.read_text()
    assert "vector" in body, "setup must ensure the pgvector extension"
    assert "0.7" in body, "setup must require pgvector >= 0.7 (halfvec)"


def test_docker_compose_defines_pgvector_pg16():
    body = COMPOSE.read_text()
    assert "pgvector/pgvector:pg16" in body
    assert "healthcheck" in body
    assert "pg_isready" in body


def test_ci_workflow_exists_and_runs_full_suite():
    assert CI.exists(), ".github/workflows/ci.yml is missing"
    body = CI.read_text()
    assert "actions/checkout" in body
    assert "3.12" in body, "CI must use Python 3.12"
    assert "setup_dev.sh" in body, "CI must exercise the same setup script"
    assert "pytest" in body
    assert "ubuntu-latest" in body


def test_ci_workflow_has_non_db_job():
    body = CI.read_text()
    for node in NON_DB_TESTS:
        assert node in body, f"CI non-DB job must run {node}"


def test_readme_documents_exact_setup_command():
    body = README.read_text()
    assert "bash scripts/setup_dev.sh" in body
    assert "pytest -q" in body
    assert "eunoia_test" in body
