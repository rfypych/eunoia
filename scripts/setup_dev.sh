#!/usr/bin/env bash
# One-command dev setup for Eunoia (T1, Rea-standard).
#
#   bash scripts/setup_dev.sh
#   .venv/bin/python -m pytest -q
#
# What it does, in order (idempotent, safe to re-run; nothing here
# drops a database):
#   1. Creates .venv (Python 3.12) and installs the package + dev
#      extras, only when the venv is missing or its imports are broken.
#   2. Brings up Postgres 16 + pgvector, in this order:
#        a. Docker Compose (pgvector/pgvector:pg16) when Docker is
#           available and nothing is already listening on 5432.
#        b. The local Postgres 16 cluster (pg_ctlcluster) otherwise.
#           The cluster is started when down, and pgvector is rebuilt
#           from ~/pgvector-build when the installed version is older
#           than 0.7.0 (the `halfvec` type needs >= 0.7.0).
#      If neither backend is available, it fails with a clear message
#      instead of leaving a half-configured environment behind.
#   3. Creates the dev (`eunoia`) and test (`eunoia_test`) databases,
#      enables the vector extension in both, and runs
#      `alembic upgrade head` on both.
#   4. Seeds the `sources` table in the dev database.
#
# Local-dev only: trust auth, no passwords. Never point this at a
# production database. It never touches the 0xrphy-box or any remote host.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"

VENV="$REPO/.venv"
PY="$(command -v python3.12 || command -v python3)"
DEV_URL="postgresql+psycopg://eunoia@localhost:5432/eunoia"
TEST_URL="postgresql+psycopg://eunoia@localhost:5432/eunoia_test"

log() { printf 'setup_dev: %s\n' "$*"; }

# pip unpacks large wheels (torch) into $TMPDIR. On machines where
# /tmp is a small tmpfs (512M here) the install fails with
# "No space left on device" even though the main disk has room.
# Point pip at a directory on the main disk unless the user set one.
if [ -z "${TMPDIR:-}" ]; then
    export TMPDIR="$HOME/.cache/pip-tmp"
    mkdir -p "$TMPDIR"
fi

# --- 1. Virtualenv -------------------------------------------------------
if [ ! -x "$VENV/bin/python" ]; then
    log "creating virtualenv with $PY ..."
    "$PY" -m venv "$VENV"
    "$VENV/bin/python" -m pip install -q -e ".[dev]"
elif ! "$VENV/bin/python" -c "import pytest, alembic" 2>/dev/null; then
    log "virtualenv is missing dev imports, installing ..."
    "$VENV/bin/python" -m pip install -q -e ".[dev]"
fi

# --- 2. Postgres ---------------------------------------------------------
port_open() {
    "$PY" -c "import socket,sys; s=socket.socket(); s.settimeout(2); sys.exit(0 if s.connect_ex(('127.0.0.1',5432))==0 else 1)" 2>/dev/null
}

docker_usable() {
    command -v docker >/dev/null 2>&1 \
        && docker compose version >/dev/null 2>&1 \
        && docker info >/dev/null 2>&1
}

ensure_pgvector_local() {
    local ver
    ver="$(sudo -u postgres psql -tAc \
        "SELECT default_version FROM pg_available_extensions WHERE name='vector'" 2>/dev/null || true)"
    if [ -z "$ver" ]; then
        log "ERROR: pgvector extension is not available in the local cluster."
        log "Install it (sudo apt install postgresql-16-pgvector), rebuild from"
        log "~/pgvector-build (sudo make -C ~/pgvector-build install), or use Docker."
        return 1
    fi
    # 0.7.0 is the minimum: the embeddings table uses the halfvec type.
    if [ "$(printf '%s\n%s\n' "0.7.0" "$ver" | sort -V | head -n1)" != "0.7.0" ]; then
        log "pgvector $ver is too old (need >= 0.7.0 for halfvec)."
        if [ -f "$HOME/pgvector-build/Makefile" ]; then
            log "rebuilding pgvector from $HOME/pgvector-build ..."
            sudo make -C "$HOME/pgvector-build" install >/dev/null
            sudo pg_ctlcluster 16 main restart
            ver="$(sudo -u postgres psql -tAc \
                "SELECT default_version FROM pg_available_extensions WHERE name='vector'")"
            log "pgvector is now $ver"
        else
            log "ERROR: no ~/pgvector-build source to rebuild from."
            log "Install pgvector >= 0.7.0, or use Docker Compose instead."
            return 1
        fi
    fi
    if [ "$(printf '%s\n%s\n' "0.7.0" "$ver" | sort -V | head -n1)" != "0.7.0" ]; then
        log "ERROR: pgvector is still $ver after rebuild, need >= 0.7.0."
        return 1
    fi
    log "pgvector $ver ok"
}

if docker_usable && ! port_open; then
    log "starting Postgres via Docker Compose ..."
    docker compose up -d db
    log "waiting for Postgres to accept connections ..."
    for _ in $(seq 1 60); do
        if docker compose exec -T db pg_isready -U eunoia -d eunoia >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    docker compose exec -T db pg_isready -U eunoia -d eunoia
    docker compose exec -T db psql -U eunoia -d eunoia -tAc \
        "SELECT 1 FROM pg_database WHERE datname='eunoia_test'" | grep -q 1 \
        || docker compose exec -T db psql -U eunoia -d eunoia -c \
            "CREATE DATABASE eunoia_test OWNER eunoia"
    docker compose exec -T db psql -U eunoia -d eunoia -c \
        "CREATE EXTENSION IF NOT EXISTS vector" >/dev/null
    docker compose exec -T db psql -U eunoia -d eunoia_test -c \
        "CREATE EXTENSION IF NOT EXISTS vector" >/dev/null
elif command -v pg_ctlcluster >/dev/null 2>&1; then
    log "using the local Postgres 16 cluster ..."
    if ! pg_lsclusters 2>/dev/null | awk '$1 == 16 && $2 == "main" && $4 == "online" {found=1} END {exit !found}'; then
        log "starting Postgres 16 cluster ..."
        sudo pg_ctlcluster 16 main start
    fi
    ensure_pgvector_local
    bash scripts/setup_dev_db.sh
    bash scripts/setup_test_db.sh
else
    log "ERROR: no Postgres backend available."
    log "Install Docker (then this script uses docker compose up), or"
    log "install Postgres 16 + pgvector >= 0.7.0 locally."
    exit 1
fi

# --- 3. Migrations on both databases -------------------------------------
log "running migrations on dev database ..."
PYTHONPATH=src DATABASE_URL="$DEV_URL" "$VENV/bin/alembic" upgrade head
log "running migrations on test database ..."
PYTHONPATH=src DATABASE_URL="$TEST_URL" "$VENV/bin/alembic" upgrade head

# --- 4. Seed dev database -------------------------------------------------
log "seeding dev database sources ..."
DATABASE_URL="$DEV_URL" "$VENV/bin/python" scripts/seed_sources.py

# --- 5. Verify -------------------------------------------------------------
"$VENV/bin/python" - <<'PYEOF'
import os, sys
sys.path.insert(0, "src")
from sqlalchemy import text
from eunoia.config import get_settings
from eunoia.db import get_engine
for name, url in (("eunoia", "postgresql+psycopg://eunoia@localhost:5432/eunoia"),
                  ("eunoia_test", "postgresql+psycopg://eunoia@localhost:5432/eunoia_test")):
    engine = get_engine(get_settings(DATABASE_URL=url))
    with engine.connect() as conn:
        ver = conn.execute(text("SELECT extversion FROM pg_extension WHERE extname='vector'")).scalar()
        tables = conn.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema='public'")).scalar()
    print(f"setup_dev: {name}: reachable, pgvector {ver}, {tables} tables")
PYEOF

log "done. Run the suite with: .venv/bin/python -m pytest -q"
