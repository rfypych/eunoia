#!/usr/bin/env bash
# Create the Eunoia test database (eunoia_test) for `pytest tests/test_models.py`.
#
# Idempotent and safe to re-run: every step checks first and only acts when
# the database, role, extension, or pg_hba line is missing. Nothing here is
# destructive — it never drops or alters an existing database.
#
# Requires sudo (runs psql as the postgres superuser, edits pg_hba.conf,
# reloads the cluster). Run from the repo root:
#   bash scripts/setup_test_db.sh
set -euo pipefail

DB=eunoia_test
ROLE=eunoia
HBA=/etc/postgresql/16/main/pg_hba.conf
HBA_LINE="host    ${DB}        ${ROLE}        127.0.0.1/32            trust"
# Whitespace-insensitive match: pg_hba.conf columns may be aligned differently.
HBA_RE="^host[[:space:]]+${DB}[[:space:]]+${ROLE}[[:space:]]+127\.0\.0\.1/32[[:space:]]+trust[[:space:]]*$"

if ! pg_lsclusters 2>/dev/null | awk '$1 == 16 && $2 == "main" && $4 == "online" {found=1} END {exit !found}'; then
    echo "Starting PostgreSQL 16 cluster..."
    sudo pg_ctlcluster 16 main start
fi

psql_super() { sudo -u postgres psql -v ON_ERROR_STOP=1 -tAc "$1"; }

if [ -z "$(psql_super "SELECT 1 FROM pg_roles WHERE rolname='${ROLE}'")" ]; then
    echo "Creating role '${ROLE}'..."
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE ROLE ${ROLE} LOGIN"
fi

if [ -z "$(psql_super "SELECT 1 FROM pg_database WHERE datname='${DB}'")" ]; then
    echo "Creating database '${DB}' (owner ${ROLE})..."
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB} OWNER ${ROLE}"
fi

echo "Ensuring vector extension in '${DB}'..."
sudo -u postgres psql -v ON_ERROR_STOP=1 -d "${DB}" -c "CREATE EXTENSION IF NOT EXISTS vector"

if ! grep -Eq "${HBA_RE}" "${HBA}"; then
    echo "Adding pg_hba.conf line for '${DB}' and reloading..."
    echo "${HBA_LINE}" | sudo tee -a "${HBA}" >/dev/null
    sudo pg_ctlcluster 16 main reload
fi

echo "Test database '${DB}' ready."
