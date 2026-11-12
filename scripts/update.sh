#!/usr/bin/env bash
# Update KSIF: pull the code, refresh Python packages, migrate the database.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VENV_PY="$ROOT/.venv/bin/python"
[ -x "$VENV_PY" ] || { echo "error: run scripts/install.sh first" >&2; exit 1; }

echo "[1/4] Fetching the latest code"
git pull --ff-only

echo "[2/4] Updating Python packages"
"$VENV_PY" -m pip install --quiet -r requirements.txt

echo "[3/4] Migrating the database"
"$VENV_PY" -c 'import main; e, db, s, _ = main.build_engine(); print("schema version", db.migrate()); db.close()'

echo "[4/4] Running the test suite"
"$VENV_PY" -m pytest -q

echo "KSIF is up to date."
