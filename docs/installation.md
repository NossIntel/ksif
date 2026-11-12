# Installation

## Requirements

- Kali Linux (rolling) or Debian 12+. Termux is experimental.
- Python 3.12 or newer.
- Root (or `sudo`) to install system packages.

## Automatic

```bash
git clone <your-repository-url> ksif
cd ksif
bash scripts/install.sh
```

The installer, in order:

1. Identifies the distribution.
2. Checks system dependencies.
3. Installs `python3 python3-venv python3-pip nmap arp-scan masscan tshark`
   from the official repositories.
4. Checks that Python is 3.12+.
5. Creates the virtual environment `.venv`.
6. Installs the Python packages from `requirements.txt`.
7. Lists which external tools are available.
8. Creates `database/`, `logs/`, `reports/`.
9. Initializes the SQLite database.
10. Runs the unit tests.
11. Prints how to start.

It does not run any scan. A package that fails to install produces a warning
and the installation continues; the matching actions will show as unavailable.

## Manual

```bash
sudo apt update
sudo apt install -y python3 python3-venv nmap arp-scan masscan tshark
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q
.venv/bin/python main.py --check
```

## Optional: PDF reports

```bash
sudo apt install -y weasyprint     # or: .venv/bin/pip install weasyprint
```

## Check and update

```bash
bash scripts/check_dependencies.sh   # tool availability
.venv/bin/python main.py --check     # tools (really executed), scope, configuration
bash scripts/update.sh               # git pull, packages, database migration, tests
```

## Uninstall

Delete the directory. KSIF writes nothing outside it.
