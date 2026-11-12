#!/usr/bin/env bash
# KSIF installer for Kali Linux / Debian (Termux: experimental).
# It installs dependencies and prepares the environment. It never runs any
# security analysis.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

APT_PACKAGES=(python3 python3-venv python3-pip nmap arp-scan masscan tshark)
TERMUX_PACKAGES=(python nmap)

step() { printf '\n\033[1;32m[%s/11]\033[0m %s\n' "$1" "$2"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$1"; }
die()  { printf '\033[1;31merror:\033[0m %s\n' "$1" >&2; exit 1; }

# 1. distribution -----------------------------------------------------------
step 1 "Identifying the distribution"
DISTRO="unknown"
if [ -n "${PREFIX:-}" ] && [ -d "${PREFIX}/bin" ] && command -v pkg >/dev/null 2>&1; then
    DISTRO="termux"
elif [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-} ${ID_LIKE:-}" in
        *kali*) DISTRO="kali" ;;
        *debian*|*ubuntu*) DISTRO="debian" ;;
    esac
fi
echo "Detected: $DISTRO"
[ "$DISTRO" = "unknown" ] && warn "unsupported distribution; system packages will not be installed"
[ "$DISTRO" = "termux" ] && warn "Termux is experimental: actions that need root will be unavailable"

SUDO=""
if [ "$(id -u)" -ne 0 ] && [ "$DISTRO" != "termux" ]; then
    command -v sudo >/dev/null 2>&1 && SUDO="sudo"
fi

# 2-4. system dependencies ---------------------------------------------------
step 2 "Checking system dependencies"
case "$DISTRO" in
    kali|debian)
        if [ "$(id -u)" -ne 0 ] && [ -z "$SUDO" ]; then
            warn "not root and sudo not found; skipping system packages"
        else
            step 3 "Installing packages from the official repositories"
            export DEBIAN_FRONTEND=noninteractive
            $SUDO apt-get update -qq
            for package in "${APT_PACKAGES[@]}"; do
                if ! $SUDO apt-get install -y -qq --no-install-recommends "$package" >/dev/null; then
                    warn "could not install $package (continuing)"
                fi
            done
        fi
        ;;
    termux)
        step 3 "Installing Termux packages"
        for package in "${TERMUX_PACKAGES[@]}"; do
            pkg install -y "$package" >/dev/null 2>&1 || warn "could not install $package (continuing)"
        done
        ;;
    *) step 3 "Skipping system packages" ;;
esac

# Python version ---------------------------------------------------------------
step 4 "Checking the Python version"
PYTHON="$(command -v python3 || command -v python || true)"
[ -n "$PYTHON" ] || die "Python 3 not found"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' \
    || die "Python 3.12 or newer is required (found $("$PYTHON" --version 2>&1))"
echo "Using $("$PYTHON" --version 2>&1)"

# 5-6. virtual environment ----------------------------------------------------
step 5 "Creating the virtual environment (.venv)"
[ -d .venv ] || "$PYTHON" -m venv .venv
VENV_PY="$ROOT/.venv/bin/python"
[ -x "$VENV_PY" ] || die "virtual environment was not created (is python3-venv installed?)"

step 6 "Installing Python packages"
"$VENV_PY" -m pip install --quiet --upgrade pip
"$VENV_PY" -m pip install --quiet -r requirements.txt

# 7. external tools ---------------------------------------------------------------
step 7 "Checking external tools"
bash "$ROOT/scripts/check_dependencies.sh"

# 8. directories ----------------------------------------------------------------
step 8 "Preparing directories"
mkdir -p database logs reports
chmod 700 database logs reports 2>/dev/null || true

# 9. database -------------------------------------------------------------------
step 9 "Initializing the SQLite database"
"$VENV_PY" -c 'import main; e, db, s, _ = main.build_engine(); print("schema version", db.migrate(), "at", s.database_path); db.close()'

# 10. tests -----------------------------------------------------------------------
step 10 "Running the basic test suite"
"$VENV_PY" -m pytest -q

# 11. instructions --------------------------------------------------------------
step 11 "Done"
cat <<EOF

KSIF is installed. No scan was run.

Next steps:
  1. Edit config/scope.yaml and list ONLY targets you own or are authorized to assess.
  2. Start KSIF:
         .venv/bin/python main.py
     Some actions need root (OS detection, ARP scan, capture):
         sudo .venv/bin/python main.py
  3. Health check at any time:
         .venv/bin/python main.py --check

KSIF starts in passive mode with an empty scope: nothing active runs until
you change both in Configuration.
EOF
